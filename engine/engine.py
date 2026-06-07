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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scope import Scope            # noqa: E402
from state import Engagement       # noqa: E402
import agent as A                  # noqa: E402

# deterministic priority by class (impact-ish); used by rank
CLASS_WEIGHT = {"rce": 100, "sqli": 90, "ssrf": 85, "auth-bypass": 85, "idor": 80,
                "deserialization": 88, "xxe": 75, "ssti": 88, "lfi": 78, "open-redirect": 40,
                "xss": 55, "cors": 45, "csrf": 50, "info-leak": 30}
ALL_PHASES = ["recon", "rank", "hunt", "validate", "report"]


class Engine:
    def __init__(self, scope_path, base, model, max_hunts, max_turns, timeout, mock=False):
        self.scope = Scope.load(scope_path)
        self.eng = Engagement(base, self.scope.name)
        self.model, self.max_hunts = model, max_hunts
        self.max_turns, self.timeout, self.mock = max_turns, timeout, mock
        self.eng.log(f"engine start | scope={self.scope.name} in={self.scope.in_scope} "
                     f"out={self.scope.out_of_scope} seeds={self.scope.seeds} mock={mock}")

    # ---------------- recon ----------------
    def recon(self):
        self.eng.set_phase("recon")
        for seed in self.scope.seeds:
            if not self.scope.in_scope_host(seed):
                self.eng.log(f"recon: seed {seed} not in scope — skip"); continue
            self.eng.log(f"recon: enumerating {seed}")
            items = self._recon_agent(seed)
            kept, dropped = [], 0
            for it in items:
                url = it.get("url", "")
                if self.scope.in_scope_host(url):
                    it.setdefault("vuln_class", "info-leak")
                    kept.append(it)
                else:
                    dropped += 1
            added = self.eng.add_surface(kept)
            self.eng.log(f"recon: {seed} -> {added} new surface item(s), {dropped} out-of-scope dropped")

    def _recon_agent(self, seed):
        if self.mock:
            return MOCK_RECON.get(seed, [])
        task = (f"You are an authorized penetration tester on a sanctioned engagement. "
                f"Enumerate the attack surface of {seed} (IN SCOPE). Crawl/probe to find endpoints and "
                f"parameters worth testing. STAY STRICTLY within these in-scope rules: "
                f"{self.scope.in_scope} (out of scope: {self.scope.out_of_scope}). "
                f"For each interesting (url, parameter), name the single most likely vulnerability class to test "
                f"(one of: {', '.join(CLASS_WEIGHT)}). "
                f"End with a fenced ```json``` array of objects: "
                f'[{{"url":"<full url>","param":"<param or empty>","vuln_class":"<class>","note":"<why>"}}].')
        r = A.run_agent(task, model=self.model, max_turns=self.max_turns, timeout=self.timeout)
        if r.get("error"):
            self.eng.log(f"recon agent error: {r['error']}"); return []
        return A.extract_json(r["result"]) or []

    # ---------------- rank ----------------
    def rank(self):
        self.eng.set_phase("rank")
        for s in self.eng.state["surface"]:
            base = CLASS_WEIGHT.get(s.get("vuln_class", ""), 20)
            s["priority"] = base + (5 if s.get("param") else 0)
        self.eng.save()
        wl = self.eng.worklist()
        self.eng.log(f"rank: {len(wl)} item(s) prioritized; top: "
                     + ", ".join(f"{s['vuln_class']}@{s['url']}" for s in wl[:3]))

    # ---------------- hunt ----------------
    def hunt(self):
        self.eng.set_phase("hunt")
        wl = self.eng.worklist()[: self.max_hunts]
        self.eng.log(f"hunt: testing {len(wl)} item(s) (cap {self.max_hunts})")
        for it in wl:
            url = it["url"]
            if not self.scope.in_scope_host(url):     # belt-and-suspenders scope gate
                self.eng.log(f"hunt: REFUSING out-of-scope {url} ({self.scope.reject_reason(url)})")
                self.eng.mark_tested(it); continue
            f = self._hunt_agent(it)
            self.eng.mark_tested(it)
            if f and f.get("vulnerable"):
                cand = {"url": url, "param": it.get("param", ""), "vuln_class": it.get("vuln_class"),
                        "severity": f.get("severity", "unknown"), "evidence": f.get("evidence", ""),
                        "request": f.get("request", "")}
                self.eng.add_candidate(cand)
                self.eng.log(f"hunt: CANDIDATE {cand['vuln_class']} @ {url}")
            else:
                self.eng.log(f"hunt: nothing on {it.get('vuln_class')}@{url}")

    def _hunt_agent(self, it):
        if self.mock:
            return MOCK_HUNT.get((it["url"], it.get("vuln_class")), {"vulnerable": False})
        task = (f"You are an authorized penetration tester on a sanctioned engagement (IN SCOPE). "
                f"Test {it['url']} (parameter `{it.get('param','')}`) for {it.get('vuln_class')}. "
                f"Use the Burp MCP tools or curl. Only claim a vulnerability if you can DEMONSTRATE real, "
                f"exploitable impact — not mere reflection, an error, or a permissive header. "
                f"End with a fenced ```json``` object: "
                f'{{"vulnerable":true|false,"severity":"low|medium|high|critical","evidence":"<what proves it>","request":"<the winning request>"}}.')
        r = A.run_agent(task, model=self.model, max_turns=self.max_turns, timeout=self.timeout)
        if r.get("error"):
            self.eng.log(f"hunt agent error ({it['url']}): {r['error']}")
            if r["error"] == "rate-limited":
                raise SystemExit("stopped: claude usage limit reached")
            return {"vulnerable": False}
        return A.extract_json(r["result"]) or {"vulnerable": False}

    # ---------------- validate ----------------
    def validate(self):
        self.eng.set_phase("validate")
        pending = [c for c in self.eng.state["candidates"]
                   if not any(cf.get("url") == c["url"] and cf.get("vuln_class") == c["vuln_class"]
                              for cf in self.eng.state["confirmed"])]
        self.eng.log(f"validate: {len(pending)} candidate(s) to adversarially verify")
        for c in pending:
            v = self._validate_agent(c)
            if v.get("real"):
                self.eng.confirm(c, v)
                self.eng.log(f"validate: CONFIRMED {c['vuln_class']} @ {c['url']} ({v.get('severity','')})")
            else:
                self.eng.log(f"validate: rejected (false positive) {c['vuln_class']} @ {c['url']} — {v.get('reason','')}")

    def _validate_agent(self, c):
        if self.mock:
            return MOCK_VALIDATE.get((c["url"], c["vuln_class"]), {"real": False, "reason": "mock-default"})
        task = (f"Adversarially verify a claimed finding (be skeptical — default to false positive if unproven). "
                f"Claim: {c['vuln_class']} at {c['url']} (param `{c.get('param','')}`). "
                f"Reported evidence: {c.get('evidence','')[:400]}. "
                f"Independently re-test it (Burp MCP / curl). Is it a REAL, exploitable vulnerability or a false positive? "
                f"End with a fenced ```json``` object: "
                f'{{"real":true|false,"severity":"low|medium|high|critical","reason":"<why>"}}.')
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
        for i, f in enumerate(c, 1):
            lines += [f"## {i}. {f.get('vuln_class','?').upper()} — {f.get('severity','?')}",
                      f"- **URL:** `{f['url']}`" + (f" (param `{f['param']}`)" if f.get("param") else ""),
                      f"- **Evidence:** {f.get('evidence','')}",
                      f"- **Request:** `{f.get('request','')}`",
                      f"- **Verifier:** {f.get('verdict',{}).get('reason','')}", ""]
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
    ap.add_argument("--phases", default=",".join(ALL_PHASES))
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-hunts", type=int, default=10)
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--mock", action="store_true", help="dry-run the orchestration with canned agent output")
    a = ap.parse_args()
    eng = Engine(a.scope, a.base, a.model, a.max_hunts, a.max_turns, a.timeout, a.mock)
    eng.run([p.strip() for p in a.phases.split(",") if p.strip()])
    print("\n" + json.dumps(eng.eng.summary(), indent=2))
    print("engagement dir:", eng.eng.dir)


if __name__ == "__main__":
    main()
