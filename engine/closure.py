#!/usr/bin/env python3
"""
closure.py — did this engagement actually cover what it discovered?

The engine reports findings. A report that lists only findings silently implies
everything else was checked and clean, which is the most dangerous default a
pentest deliverable can have. `tested: 47` cannot answer "which classes were
never tried on host X" — this can, and the report renders its caveats from it
rather than from hand-written prose.

    CLOSE CLEAN when  every discovered (host, vuln_class) pair has a verdict
    otherwise         MARKED, and the gaps ship as caveats

`coverage_complete` is a HARD gate. An engagement with one geo-blocked host
never closes clean; it closes MARKED and says so. That is deliberate — a caveat
that ships is worth more than a clean-looking report that quietly omits what
nobody could reach.

Pure functions over the state dict, testable without running agents.
Run `python3 engine/closure.py` for the self-check.
"""

# A (host, vuln_class) pair is only "covered" by one of these verdicts.
# BLOCKED is deliberately absent — it is a gap, and gaps become caveats.
COVERED = {"clean", "finding", "not_applicable", "out_of_scope"}
VERDICTS = COVERED | {"blocked"}


def _host(url):
    """Bare host (port included) from a URL, tolerant of scheme-less input.

    Recorders and the expectation set must agree on this, or a covered pair
    silently reads as never-tested.
    """
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0].split("?", 1)[0]


def expected_coverage(state):
    """Every (host, vuln_class) the run discovered, and therefore owes a verdict."""
    return {(_host(s["url"]), s.get("vuln_class", "")) for s in state.get("surface", [])
            if s.get("vuln_class")}


def coverage_gaps(state):
    """Pairs with no verdict, or an explicitly blocked one. Sorted for stable reports."""
    cov = state.get("coverage", {})
    gaps = []
    for host, cls in expected_coverage(state):
        rec = cov.get(f"{host}|{cls}")
        if rec is None:
            gaps.append({"host": host, "vuln_class": cls, "state": "never_tested", "note": ""})
        elif rec.get("verdict") == "blocked":
            gaps.append({"host": host, "vuln_class": cls, "state": "blocked",
                         "note": rec.get("note", "")})
    return sorted(gaps, key=lambda g: (g["host"], g["vuln_class"]))


def coverage_complete(state):
    return not coverage_gaps(state)


def evaluate(state):
    """{clean: bool, reason: str, gaps: [...]} — the closure verdict for the report."""
    gaps = coverage_gaps(state)
    if not gaps:
        return {"clean": True, "gaps": [],
                "reason": "every discovered (host, vulnerability class) pair reached a verdict"}
    blocked = sum(1 for g in gaps if g["state"] == "blocked")
    never = len(gaps) - blocked
    bits = ([f"{blocked} blocked"] if blocked else []) + ([f"{never} never tested"] if never else [])
    return {"clean": False, "gaps": gaps,
            "reason": f"{len(gaps)} coverage gap(s): " + ", ".join(bits)}


def render_caveats(state, decision=None):
    """The 'not tested' section, generated from the ledger rather than written by hand."""
    d = decision or evaluate(state)
    if d["clean"]:
        return ("## Coverage\n\nEvery discovered (host, vulnerability class) pair reached a "
                "verdict. No coverage caveats apply.\n")

    gaps = d["gaps"]
    blocked = [g for g in gaps if g["state"] == "blocked"]
    never = [g for g in gaps if g["state"] == "never_tested"]
    out = ["## Not tested — do not read as passing\n",
           "**This engagement did not reach full coverage.** The surface below was discovered "
           "and never cleared.\n"]
    if blocked:
        out.append("\n**Blocked — reachable surface that could not be assessed:**\n")
        for g in blocked:
            out.append(f"- `{g['host']}` · {g['vuln_class']}" + (f" — {g['note']}" if g["note"] else ""))
    if never:
        out.append("\n**Never tested — discovered but never reached:**\n")
        for g in never:
            out.append(f"- `{g['host']}` · {g['vuln_class']}")
    out.append("\nAbsence of a finding above is not evidence of absence of a vulnerability.\n")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Assertions — the gate is hard, the marked terminal is reachable and marked,
# and a gap survives into the report. Run: python3 engine/closure.py
# --------------------------------------------------------------------------
def _demo():
    def st(surface=(), coverage=None):
        return {"surface": [{"url": u, "vuln_class": c} for u, c in surface],
                "coverage": coverage or {}}

    # a single untested pair blocks clean closure — the gate is hard
    s = st([("https://a.test/x", "idor"), ("https://b.test/y", "ssrf")],
           {"a.test|idor": {"verdict": "clean"}})
    d = evaluate(s)
    assert not d["clean"] and len(d["gaps"]) == 1 and d["gaps"][0]["host"] == "b.test"
    assert "never tested" in d["reason"]

    # blocked never counts as covered, and its note reaches the report
    s2 = st([("https://a.test/x", "idor")],
            {"a.test|idor": {"verdict": "blocked", "note": "geo-fenced at edge"}})
    assert not coverage_complete(s2)
    out = render_caveats(s2)
    assert "do not read as passing" in out and "geo-fenced at edge" in out

    # out_of_scope and not_applicable ARE verdicts — they close cleanly
    s3 = st([("https://a.test/x", "idor"), ("https://a.test/y", "xss")],
            {"a.test|idor": {"verdict": "out_of_scope"}, "a.test|xss": {"verdict": "not_applicable"}})
    assert evaluate(s3)["clean"], "a recorded verdict must close, even a negative one"
    assert "No coverage caveats apply" in render_caveats(s3)

    # host normalisation must match between recorder and expectation (port included)
    assert _host("https://h.test:8443/a?b=1") == "h.test:8443"
    s4 = st([("https://h.test:8443/a", "idor")], {"h.test:8443|idor": {"verdict": "clean"}})
    assert evaluate(s4)["clean"], "recorder and expectation must agree on host form"

    # surface with no vuln_class owes nothing
    assert evaluate({"surface": [{"url": "https://a.test/"}], "coverage": {}})["clean"]

    print("closure.py: all assertions pass")


if __name__ == "__main__":
    _demo()
