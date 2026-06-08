#!/usr/bin/env python3
"""
engine.py — autonomous engagement orchestrator.

Deterministic control flow (scope, state, dispatch, ranking, dedup, reporting);
LLM only for recon/hunt/validate. Phases:

  scope -> recon -> rank -> hunt -> validate -> report

Scope is enforced in code at every boundary: recon discoveries are filtered to
in-scope hosts, and no hunt agent is ever dispatched at an out-of-scope target.
State is persisted after every step, so a run is auditable and resumable.

  python3 engine/engine.py --scope engine/engagement.example.json --mock        # dry-run the flow (no agents)
  python3 engine/engine.py --scope my-engagement.json --max-hunts 8             # live (needs Burp + claude budget)
  python3 engine/engine.py --scope my-engagement.json --phases hunt,validate,report   # resume later phases
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scope import Scope            # noqa: E402
from state import Engagement       # noqa: E402
import agent as A                  # noqa: E402

# deterministic priority by class (impact-ish); used by rank
CLASS_WEIGHT = {"rce": 100, "sqli": 90, "ssrf": 85, "auth-bypass": 85, "idor": 80,
                "deserialization": 88, "xxe": 75, "ssti": 88, "lfi": 78, "llm-ai": 70,
                "graphql": 65, "open-redirect": 40, "xss": 55, "cors": 45, "csrf": 50,
                "info-leak": 30}
# OSINT (subdomain/asset enum) is a SEPARATE concern (Claude-OSINT) — not in the engine flow.
# DEFAULT = recon -> rank -> map (deterministic, ~free): map the surface to the skill arsenal and
# SHOW it. The operator focuses their effort from there. hunt/validate/report are OPT-IN (--hunt).
ALL_PHASES = ["recon", "rank", "map", "hunt", "validate", "report"]
DEFAULT_PHASES = ["recon", "rank", "map"]


class Engine:
    def __init__(self, scope_path, base, model, max_hunts, max_turns, timeout, mock=False,
                 allow_intrusive=False, parallel=3, expand=False):
        self.scope = Scope.load(scope_path)
        self.eng = Engagement(base, self.scope.name)
        self.model, self.max_hunts = model, max_hunts
        self.max_turns, self.timeout, self.mock = max_turns, timeout, mock
        self.allow_intrusive = allow_intrusive
        self.expand = expand
        self.parallel = max(1, parallel)
        self.eng.log(f"engine start | scope={self.scope.name} in={self.scope.in_scope} "
                     f"out={self.scope.out_of_scope} seeds={self.scope.seeds} mock={mock} "
                     f"intrusive={'ALLOWED' if allow_intrusive else 'READ-ONLY (default)'}")

    # ---------------- rules of engagement (injected into every agent) ----------------
    def _roe(self):
        hosts = ", ".join(self.scope.in_scope)
        roe = ("RULES OF ENGAGEMENT (mandatory — authorized SOW):\n"
               f"- SCOPE: ONLY these hosts are in scope: {hosts}. NEVER send a request to ANY other host "
               "(no third-party APIs / CDNs / SaaS such as emailjs, salesforce, google, etc.), even to 'prove' a "
               "finding. If proof would require touching an out-of-scope host/service, DO NOT do it — report the "
               "finding but set proof_note='would require out-of-scope action (NOT performed)'.\n")
        if not self.allow_intrusive:
            roe += ("- READ-ONLY / NON-DESTRUCTIVE: do NOT perform any state-changing or intrusive action — no sending "
                    "emails, no writes/updates/deletes, no cache purge/revalidate, no account creation, no spam, no "
                    "flooding/DoS, and do NOT exercise exposed credentials. Demonstrate a finding with the minimum safe, "
                    "read-only evidence (SHOW that something is exposed; do NOT use it). A finding you cannot demonstrate "
                    "safely read-only -> report it with proof_note='requires intrusive validation (NOT performed)'.\n")
        else:
            roe += "- Intrusive actions are AUTHORIZED for this run; still prefer the least-impactful PoC and log what you did.\n"
        return roe

    def _scope_audit(self, f):
        """Deterministic safety net: which out-of-scope hosts did the agent's PoC touch?"""
        blob = " ".join([str(f.get("request", "")), str(f.get("evidence", "")),
                         " ".join(f.get("hosts_contacted") or [])])
        hosts = set(re.findall(r'https?://([A-Za-z0-9.\-]+)', blob)) | set(f.get("hosts_contacted") or [])
        return sorted({h for h in hosts if h and not self.scope.in_scope_host(h)})

    # ---------------- osint (deterministic scope expansion) ----------------
    def osint(self):
        self.eng.set_phase("osint")
        if self.mock:
            self.eng.state["targets"] = [{"host": "localhost", "url": s, "status": 200, "tech": []}
                                         for s in self.scope.seeds]
            self.eng.save(); self.eng.log(f"osint(mock): {len(self.eng.state['targets'])} target(s)")
            return
        import osint as O  # subdomain/asset enum -> live-host + tech map (subfinder/assetfinder/crt.sh + curl)
        targets = O.osint(self.scope, log=self.eng.log)
        self.eng.state["targets"] = targets
        self.eng.save()
        self.eng.log(f"osint: {len(targets)} live in-scope target(s) -> recon")

    # ---------------- OSINT->recon bridge (opt-in --expand) ----------------
    def _expand_scope(self):
        """OPT-IN bridge: enumerate subdomains via the (separate) osint module, probe liveness,
        and set seeds to every LIVE in-scope host so recon runs on each. Off by default — OSINT is
        a separate concern (Claude-OSINT); this just ingests its result when you want one tool to do
        it. The apex alone is usually a marketing page; the real surface is on subdomains."""
        import osint as O
        from urllib.parse import urlparse
        apexes = {".".join((urlparse(s).hostname or "").split(".")[-2:]) for s in self.scope.seeds}
        subs = set()
        for apex in sorted(a for a in apexes if a):
            subs |= O.enumerate_subdomains(apex, log=self.eng.log)
        in_scope = [s for s in sorted(subs) if self.scope.in_scope_host(s)]
        self.eng.log(f"expand: {len(subs)} subdomain(s) -> {len(in_scope)} in scope; probing liveness...")
        live, _ = O.probe_hosts(in_scope, log=self.eng.log)
        new_seeds = sorted({t["url"] for t in live if t.get("url")})
        if new_seeds:
            self.scope.seeds = new_seeds
            self.eng.log(f"expand: recon will run on {len(new_seeds)} live host(s): "
                         + ", ".join(urlparse(u).hostname for u in new_seeds[:10]))

    # ---------------- recon (deterministic, SPA-aware, per target) ----------------
    def recon(self):
        self.eng.set_phase("recon")
        if self.mock:
            items = []
            for seed in self.scope.seeds:
                items += [it for it in MOCK_RECON.get(seed, []) if self.scope.in_scope_host(it.get("url", ""))]
            self.eng.add_surface(items)
            self.eng.log(f"recon(mock): {len(items)} item(s)")
            return
        if self.expand:
            self._expand_scope()
        import recon as R, osint as O  # deterministic recon: service/tech + endpoints + secrets + params
        from urllib.parse import urlparse
        # service / tech fingerprint of the seed target(s) — per-target (NOT subdomain enum)
        seed_hosts = sorted({urlparse(s).hostname for s in self.scope.seeds if urlparse(s).hostname})
        tech, _ = O.probe_hosts(seed_hosts, log=self.eng.log)
        self.eng.state["targets"] = tech
        self.eng.save()
        for t in tech:
            self.eng.log(f"recon: service {t.get('host')} [{t.get('status')}] · {', '.join(t.get('tech', [])) or 'tech?'}")
        plat = R.platform_recon(self.scope, log=self.eng.log)        # .well-known / Firebase / OAuth / robots
        api = R.openapi_recon(self.scope, log=self.eng.log)          # OpenAPI schema -> categorized + auth-sweep
        endpoints, oos = R.spa_recon(self.scope, log=self.eng.log)   # current API endpoints + JS secrets
        params = R.gather_params(self.scope, log=self.eng.log)       # all input parameters (gau historical)
        # categorize every (endpoint | param) into its applicable attack classes, expand to work units
        expanded = list(api) + list(plat)                            # api + platform items are already categorized
        for it in endpoints:
            for cls in R.classify_all(it):
                e = dict(it); e["vuln_class"] = cls; e.pop("vuln_classes", None); expanded.append(e)
        for it in params:
            for cls in R.classes_for_param(it.get("param", ""), it.get("url", "")):
                e = dict(it); e["vuln_class"] = cls; expanded.append(e)
        added = self.eng.add_surface(expanded)
        if oos:
            self.eng.log(f"recon: {len(oos)} out-of-scope host(s) seen, NOT tested: {', '.join(oos[:8])}")
        self.eng.log(f"recon: {len(api)} api + {len(plat)} platform + {len(endpoints)} endpoint + "
                     f"{len(params)} param -> {added} categorized (target,class) work unit(s)")

    # ---------------- rank ----------------
    def rank(self):
        self.eng.set_phase("rank")
        for s in self.eng.state["surface"]:
            base = CLASS_WEIGHT.get(s.get("vuln_class", ""), 20)
            s["priority"] = base + (5 if s.get("param") else 0) + (55 if s.get("source") == "secret" else 0)
        self.eng.save()
        wl = self.eng.worklist()
        self.eng.log(f"rank: {len(wl)} item(s) prioritized; top: "
                     + ", ".join(f"{s['vuln_class']}@{s['url']}" for s in wl[:3]))

    # ---------------- map (arsenal categorization — the default deliverable) ----------------
    def map(self):
        """Categorize the surface against the skill arsenal and SHOW it: per target ->
        applicable hunt-* skill(s) + first curl. This is where the operator focuses; the
        engine does NOT auto-test by default (run with --hunt to spend agents)."""
        self.eng.set_phase("map")
        import skill_map as SM
        from collections import OrderedDict
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        groups = OrderedDict()
        for s in sorted(self.eng.state["surface"], key=lambda z: -z.get("priority", 0)):
            key = (s["url"], s.get("param", ""))
            g = groups.setdefault(key, {"classes": [], "src": s.get("source", "")})
            if s["vuln_class"] not in g["classes"]:
                g["classes"].append(s["vuln_class"])
        tech_sk = SM.tech_skills(tech)
        lines = [f"# Arsenal map — {self.scope.name}", "",
                 f"**Service / tech:** {', '.join(tech) or '?'}  ",
                 f"**Tech-wide skills:** {', '.join('`'+s+'`' for s in tech_sk) or 'none'}  ",
                 f"**Attack surface:** {len(groups)} target(s). For each: applicable skill(s) + the first curl.",
                 "", "> Active testing is curl-first; Burp MCP only for OOB/blind/fuzzing. "
                 "Run the engine with `--hunt` to auto-test these with agents (skills-off, parallel).", ""]
        self.eng.log(f"map: ARSENAL — tech-skills: {', '.join(tech_sk) or 'none'} | {len(groups)} target(s):")
        for (url, param), g in groups.items():
            label = param if param else "(endpoint)"
            per = "  ".join(f"{c}→{','.join(SM.skills_for(c))}" for c in g["classes"])
            self.eng.log(f"map:   {label:16.16s} {url[:42]:42.42s}  {per}")
            lines.append(f"## `{label}`  —  {', '.join(g['classes'])}")
            lines.append(f"- **URL:** `{url}`" + (f"  ·  source: {g['src']}" if g["src"] else ""))
            for c in g["classes"]:
                lines.append(f"- **{c}** → {', '.join('`'+s+'`' for s in SM.skills_for(c))}  ·  "
                             f"`{SM.probe_for(c, url, param)}`")
            lines.append("")
        path = os.path.join(self.eng.dir, "arsenal.md")
        open(path, "w").write("\n".join(lines))
        self.eng.log(f"map: wrote arsenal map -> {path}  ← focus your 20% here (or run --hunt to auto-test)")

    # ---------------- parallel runner ----------------
    def _run_parallel(self, fn, items):
        """Run fn(item) across self.parallel workers; yield (item, result) as each finishes.
        Workers do only the slow agent call (NO state mutation); the caller serializes all
        state writes, so there's no race on state.json."""
        if self.parallel <= 1 or len(items) <= 1:
            for it in items:
                yield it, fn(it)
            return
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.parallel) as ex:
            futs = {ex.submit(fn, it): it for it in items}
            for fut in as_completed(futs):
                it = futs[fut]
                try:
                    yield it, fut.result()
                except Exception as e:
                    self.eng.log(f"  worker error on {it.get('url')}: {e}")
                    yield it, {}

    # ---------------- hunt ----------------
    def hunt(self):
        self.eng.set_phase("hunt")
        wl = self.eng.worklist()[: self.max_hunts]
        todo = []
        for it in wl:
            if not self.scope.in_scope_host(it["url"]):     # belt-and-suspenders scope gate
                self.eng.log(f"hunt: REFUSING out-of-scope {it['url']} ({self.scope.reject_reason(it['url'])})")
                self.eng.mark_tested(it)
            else:
                todo.append(it)
        self.eng.log(f"hunt: testing {len(todo)} item(s), {self.parallel} at a time")
        for it, f in self._run_parallel(self._hunt_agent, todo):
            self.eng.mark_tested(it)
            if f and f.get("rate_limited"):
                self.eng.log("hunt: ⚠ claude usage limit hit — remaining results may be partial")
            if f and f.get("vulnerable"):
                oos = self._scope_audit(f)
                cand = {"url": it["url"], "param": it.get("param", ""), "vuln_class": it.get("vuln_class"),
                        "severity": f.get("severity", "unknown"), "evidence": f.get("evidence", ""),
                        "request": f.get("request", ""), "proof_note": f.get("proof_note", ""),
                        "scope_warning": oos or None}
                self.eng.add_candidate(cand)
                self.eng.log((f"hunt: ⚠ CANDIDATE {cand['vuln_class']} @ {it['url']} — PoC touched OUT-OF-SCOPE "
                              f"host(s): {', '.join(oos)} (flagged)") if oos
                             else f"hunt: CANDIDATE {cand['vuln_class']} @ {it['url']}")
            else:
                self.eng.log(f"hunt: nothing on {it.get('vuln_class')}@{it['url']}")

    def _hunt_agent(self, it):
        if self.mock:
            return MOCK_HUNT.get((it["url"], it.get("vuln_class")), {"vulnerable": False})
        import skill_map as SM
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        skills = SM.skills_for(it.get("vuln_class", "")) + SM.tech_skills(tech)
        probe = SM.probe_for(it.get("vuln_class", ""), it["url"], it.get("param"))
        task = (self._roe() + "\n"
                f"TASK: Test {it['url']} (parameter `{it.get('param','')}`) for {it.get('vuln_class')}, strictly "
                f"within the rules of engagement above. Apply the methodology of: {', '.join(skills)}. "
                f"curl-FIRST: use curl for your requests; use the Burp MCP tools ONLY if you genuinely need "
                f"OOB/blind/fuzzing (e.g. Collaborator for blind SSRF/XXE). Starter probe: {probe} . "
                f"Only claim a vulnerability if you can DEMONSTRATE real, exploitable impact (not mere reflection, "
                f"an error, or a permissive header) using ONLY in-scope, read-only actions. "
                f"End with a fenced ```json``` object: "
                f'{{"vulnerable":true|false,"severity":"low|medium|high|critical","evidence":"<what proves it>",'
                f'"request":"<the winning request>","hosts_contacted":["every host you sent a request to"],'
                f'"proof_note":"<empty, or why proof was limited by scope/read-only>"}}.')
        r = A.run_agent(task, model=self.model, max_turns=self.max_turns, timeout=self.timeout)
        if r.get("error"):
            self.eng.log(f"hunt agent error ({it['url']}): {r['error']}")
            return {"vulnerable": False, "rate_limited": r["error"] == "rate-limited"}
        return A.extract_json(r["result"]) or {"vulnerable": False}

    # ---------------- validate ----------------
    def validate(self):
        self.eng.set_phase("validate")
        pending = [c for c in self.eng.state["candidates"]
                   if not any(cf.get("url") == c["url"] and cf.get("vuln_class") == c["vuln_class"]
                              for cf in self.eng.state["confirmed"])]
        self.eng.log(f"validate: {len(pending)} candidate(s) to adversarially verify, {self.parallel} at a time")
        for c, v in self._run_parallel(self._validate_agent, pending):
            if v and v.get("real"):
                if v.get("severity"):
                    c["severity"] = v["severity"]  # use the validator's CALIBRATED severity, not the hunt's
                self.eng.confirm(c, v)
                self.eng.log(f"validate: CONFIRMED {c['vuln_class']} @ {c['url']} ({v.get('severity','')})"
                             + (f" ⚠ scope-flagged: {', '.join(c['scope_warning'])}" if c.get('scope_warning') else ''))
            else:
                self.eng.log(f"validate: rejected (false positive) {c['vuln_class']} @ {c['url']} — "
                             f"{(v or {}).get('reason', 'no verdict')}")

    def _validate_agent(self, c):
        if self.mock:
            return MOCK_VALIDATE.get((c["url"], c["vuln_class"]), {"real": False, "reason": "mock-default"})
        task = (self._roe() + "\n"
                f"Adversarially verify a claimed finding (be skeptical — default to false positive if unproven). "
                f"Claim: {c['vuln_class']} at {c['url']} (param `{c.get('param','')}`). "
                f"Reported evidence: {c.get('evidence','')[:400]}. "
                f"Independently re-test it WITHIN the rules of engagement above (in-scope + read-only only). If the only "
                f"proof would require an out-of-scope host or an intrusive action, treat the impact as UNPROVEN and lower "
                f"the severity. Is it a REAL, exploitable vulnerability or a false positive? "
                f"End with a fenced ```json``` object: "
                f'{{"real":true|false,"severity":"low|medium|high|critical","reason":"<why, incl. any scope/intrusive caveat>"}}.')
        r = A.run_agent(task, model=self.model, max_turns=self.max_turns, timeout=self.timeout)
        if r.get("error"):
            self.eng.log(f"validate agent error: {r['error']}")
            return {"real": False, "reason": f"verify error: {r['error']}"}
        return A.extract_json(r["result"]) or {"real": False, "reason": "no verdict"}

    # ---------------- report ----------------
    def report(self):
        self.eng.set_phase("report")
        c = self.eng.state["confirmed"]
        s = self.eng.summary()
        lines = [f"# Engagement report — {self.scope.name}", "",
                 f"In scope: `{'`, `'.join(self.scope.in_scope)}`  ",
                 f"Surface mapped: {s['surface']} · tested: {s['tested']} · "
                 f"candidates: {s['candidates']} · **confirmed: {s['confirmed']}**", ""]
        if not c:
            lines += ["No confirmed findings.", ""]
        flagged = [f for f in c if f.get("scope_warning")]
        if flagged:
            lines += [f"> ⚠️ **{len(flagged)} finding(s) flagged: PoC referenced an out-of-scope host — "
                      f"review before reporting to the client.**", ""]
        for i, f in enumerate(c, 1):
            block = [f"## {i}. {f.get('vuln_class','?').upper()} — {f.get('severity','?')}",
                     f"- **URL:** `{f['url']}`" + (f" (param `{f['param']}`)" if f.get("param") else "")]
            if f.get("scope_warning"):
                block.append(f"- ⚠️ **SCOPE WARNING:** PoC referenced out-of-scope host(s): "
                             f"`{'`, `'.join(f['scope_warning'])}` — verify the in-scope finding holds without them.")
            if f.get("proof_note"):
                block.append(f"- **Proof note:** {f['proof_note']}")
            block += [f"- **Evidence:** {f.get('evidence','')}",
                      f"- **Request:** `{f.get('request','')}`",
                      f"- **Verifier:** {f.get('verdict',{}).get('reason','')}", ""]
            lines += block
        path = os.path.join(self.eng.dir, "report.md")
        open(path, "w").write("\n".join(lines))
        self.eng.log(f"report: wrote {len(c)} confirmed finding(s) -> {path}")
        return path

    def run(self, phases):
        for ph in ALL_PHASES:
            if ph in phases:
                getattr(self, ph)()
        self.eng.set_phase("done")
        self.eng.log(f"engine done | {self.eng.summary()}")


# ---- mock fixtures for --mock flow validation (no agents) ----
MOCK_RECON = {
    "http://localhost:3002": [
        {"url": "http://localhost:3002/api/account?id=5", "param": "id", "vuln_class": "idor", "note": "id param"},
        {"url": "http://localhost:3002/redirect?next=x", "param": "next", "vuln_class": "open-redirect", "note": "redirect"},
        {"url": "http://localhost:3002/search?q=x", "param": "q", "vuln_class": "xss", "note": "reflected"},
        {"url": "http://evil.example/x", "param": "", "vuln_class": "sqli", "note": "OUT OF SCOPE — should be dropped"},
    ]
}
MOCK_HUNT = {
    ("http://localhost:3002/api/account?id=5", "idor"): {"vulnerable": True, "severity": "high", "evidence": "id=N returns other users' PII", "request": "GET /api/account?id=6"},
    ("http://localhost:3002/redirect?next=x", "open-redirect"): {"vulnerable": True, "severity": "medium", "evidence": "302 to external", "request": "GET /redirect?next=//evil.com"},
    ("http://localhost:3002/search?q=x", "xss"): {"vulnerable": False},
}
MOCK_VALIDATE = {
    ("http://localhost:3002/api/account?id=5", "idor"): {"real": True, "severity": "high", "reason": "confirmed PII exposure for arbitrary id"},
    ("http://localhost:3002/redirect?next=x", "open-redirect"): {"real": False, "reason": "only redirects to relative paths on re-test (false positive)"},
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True, help="engagement/scope JSON (name, in_scope, out_of_scope, seeds)")
    ap.add_argument("--base", default="~/.bughunter-engagements")
    ap.add_argument("--phases", default=None,
                    help="explicit phase list; default is recon,rank,map (add --hunt to test)")
    ap.add_argument("--hunt", action="store_true",
                    help="OPT-IN: after mapping, auto-test with agents (recon,rank,map,hunt,validate,report)")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-hunts", type=int, default=10)
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--mock", action="store_true", help="dry-run the orchestration with canned agent output")
    ap.add_argument("--allow-intrusive", action="store_true",
                    help="permit state-changing PoCs (emails/writes/purges). DEFAULT OFF = read-only, non-destructive.")
    ap.add_argument("--parallel", type=int, default=3, help="concurrent hunt/validate agents (default 3)")
    ap.add_argument("--expand", action="store_true",
                    help="OSINT bridge: enumerate subdomains, probe, and recon every live in-scope host "
                         "(the apex is usually just marketing; the real surface is on subdomains)")
    a = ap.parse_args()
    if a.phases:
        phases = [p.strip() for p in a.phases.split(",") if p.strip()]
    elif a.hunt:
        phases = ALL_PHASES                       # full: map then auto-test
    else:
        phases = DEFAULT_PHASES                   # default: recon -> rank -> map, then STOP for the operator
    eng = Engine(a.scope, a.base, a.model, a.max_hunts, a.max_turns, a.timeout, a.mock,
                 a.allow_intrusive, a.parallel, a.expand)
    eng.run(phases)
    print("\n" + json.dumps(eng.eng.summary(), indent=2))
    print("engagement dir:", eng.eng.dir)


if __name__ == "__main__":
    main()
