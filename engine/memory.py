#!/usr/bin/env python3
"""
memory.py — autopilot ledger: cross-engagement capture + skip decisions.

Lets the autonomous hunt loop skip provably-wasteful agent calls: re-confirming a
known finding, or re-testing a vuln_class that never pays off on this tech stack.
Capture is harvested from the engine's own state; skip is gated (off unless the
engine passes use_memory, i.e. token-saving modes only).

Storage (~/.claude/bughunter/memory/, override BUGHUNTER_MEMORY_DIR):
  findings.jsonl       one row per confirmed finding (cross-target)
  negatives.jsonl      (host, stack_sig, vuln_class) hunted -> not confirmed
  targets/<host>.json  per-target rollup for /pickup

stdlib-only; imports nothing from sibling engine modules.
"""
import fcntl
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

SCHEMA_VERSION = 1
MAX_BYTES = 10 * 1024 * 1024        # rotate a JSONL past 10 MB
KEEP = 3                            # backups kept: .1 (newest) .. .3
DEAD_CLASS_THRESHOLD = 5           # negatives before a (stack,class) is "dead"


def _root():
    return os.path.expanduser(os.environ.get("BUGHUNTER_MEMORY_DIR", "~/.claude/bughunter/memory"))


def _paths():
    root = _root()
    os.makedirs(os.path.join(root, "targets"), exist_ok=True)
    return root


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host(url):
    u = url or ""
    if "://" not in u:
        u = "//" + u
    return (urlparse(u).hostname or "").lower().rstrip(".")


def _stack_sig(tech_stack):
    return "|".join(sorted({t.lower() for t in (tech_stack or []) if t}))


def _rotate_if_needed(path, max_bytes=MAX_BYTES, keep=KEEP):
    try:
        if os.path.getsize(path) < max_bytes:
            return
    except FileNotFoundError:
        return
    oldest = f"{path}.{keep}"
    if os.path.exists(oldest):
        os.remove(oldest)
    for i in range(keep - 1, 0, -1):
        s, d = f"{path}.{i}", f"{path}.{i + 1}"
        if os.path.exists(s):
            os.replace(s, d)
    os.replace(path, f"{path}.1")


def _append(path, obj):
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    lock = str(path) + ".lock"
    lfd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lfd, fcntl.LOCK_EX)
        _rotate_if_needed(path)                      # now inside the lock: no cross-process rename race
        with open(path, "ab") as f:
            f.write(line.encode("utf-8"))
    finally:
        fcntl.flock(lfd, fcntl.LOCK_UN)
        os.close(lfd)


def _read(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                record = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                out.append(record)
    return out


def _valid_finding(e):
    if not (e.get("host") and e.get("url") and e.get("vuln_class")):
        return False
    try:
        datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
    except Exception:
        return False
    return isinstance(e.get("tech_stack", []), list)


def record_finding(engagement, host, tech_stack, finding, verdict):
    """Capture one confirmed finding. Dedup on (host,url,param,vuln_class)."""
    root = _paths()
    fp = os.path.join(root, "findings.jsonl")
    entry = {
        "schema_version": SCHEMA_VERSION, "ts": _now(), "engagement": engagement,
        "host": host or _host(finding.get("url", "")), "url": finding.get("url", ""),
        "param": finding.get("param", ""), "vuln_class": finding.get("vuln_class", ""),
        "technique": finding.get("technique", ""),
        "severity": (verdict or {}).get("severity") or finding.get("severity", ""),
        "verdict_reason": (verdict or {}).get("reason", ""),
        "tech_stack": list(tech_stack or []),
        "evidence_ref": finding.get("evidence_ref", ""),
    }
    if not _valid_finding(entry):
        print(f"memory: skipping invalid finding {entry.get('url')!r}", file=sys.stderr)
        return False
    key = (entry["host"], entry["url"], entry["param"], entry["vuln_class"])
    for e in _read(fp):
        if (e.get("host"), e.get("url"), e.get("param"), e.get("vuln_class")) == key:
            return False
    _append(fp, entry)
    return True


def _parse_key(k):
    """state 'url|param|class' -> (host, vuln_class)."""
    url, _, rest = k.partition("|")
    _param, _, cls = rest.partition("|")
    return _host(url), cls


def _write_rollup(host, tech_stack, tested, confirmed):
    root = _paths()
    p = os.path.join(root, "targets", f"{host}.json")
    prev = {}
    if os.path.exists(p):
        try:
            prev = json.load(open(p))
        except Exception:
            prev = {}
    hc_conf = [f for f in confirmed if _host(f.get("url", "")) == host]
    doc = {
        "schema_version": SCHEMA_VERSION, "host": host,
        "first_seen": prev.get("first_seen", _now()), "last_seen": _now(),
        "sessions": prev.get("sessions", 0) + 1, "tech_stack": list(tech_stack or []),
        "tested": [k for k in tested if _parse_key(k)[0] == host],
        "confirmed": [{"url": f.get("url"), "param": f.get("param", ""),
                       "vuln_class": f.get("vuln_class"), "severity": f.get("severity", "")}
                      for f in hc_conf],
    }
    tmp = p + ".tmp"
    json.dump(doc, open(tmp, "w"), indent=2)
    os.replace(tmp, p)


def record_run(engagement, tech_stack, tested, confirmed):
    """End-of-run capture: negatives for tested-but-unconfirmed classes + per-host rollup."""
    root = _paths()
    sig = _stack_sig(tech_stack)
    tested_hc = {_parse_key(k) for k in tested}
    confirmed_hc = {(_host(f.get("url", "")), f.get("vuln_class", "")) for f in confirmed}
    neg = os.path.join(root, "negatives.jsonl")
    for host, cls in tested_hc:
        if cls and (host, cls) not in confirmed_hc:
            _append(neg, {"schema_version": SCHEMA_VERSION, "ts": _now(),
                          "host": host, "stack_sig": sig, "vuln_class": cls,
                          "engagement": engagement})
    for host in {h for h, _ in tested_hc} | {h for h, _ in confirmed_hc}:
        if host:
            _write_rollup(host, tech_stack, tested, confirmed)


def skip_decision(host, tech_stack, item):
    """Should the hunt loop skip this worklist item? Off-path returns skip=False."""
    root = _paths()
    url, param, cls = item.get("url", ""), item.get("param", ""), item.get("vuln_class", "")
    # 1) known-confirmed -> carry the finding forward, no agent
    for e in _read(os.path.join(root, "findings.jsonl")):
        if (e.get("host"), e.get("url"), e.get("param"), e.get("vuln_class")) == (host, url, param, cls):
            carry = {"url": url, "param": param, "vuln_class": cls,
                     "severity": e.get("severity", ""), "evidence": e.get("verdict_reason", ""),
                     "verdict_reason": e.get("verdict_reason", ""),
                     "verdict": {"real": True, "severity": e.get("severity", ""),
                                 "reason": e.get("verdict_reason", ""), "from_memory": True}}
            return {"skip": True, "reason": "known-confirmed", "carry": carry}
    # 2) dead-class: >= threshold negatives for (stack_sig, cls) AND zero confirmations for it
    sig = _stack_sig(tech_stack)
    negatives = _read(os.path.join(root, "negatives.jsonl"))
    distinct = {
        (entry.get("engagement") or index, entry.get("host"))
        for index, entry in enumerate(negatives)
        if entry.get("stack_sig") == sig and entry.get("vuln_class") == cls
    }
    negs = len(distinct)
    if negs >= DEAD_CLASS_THRESHOLD:
        confirmed_here = any(_stack_sig(e.get("tech_stack", [])) == sig and e.get("vuln_class") == cls
                             for e in _read(os.path.join(root, "findings.jsonl")))
        if not confirmed_here:
            return {"skip": True, "reason": f"dead-class ({negs} negatives, 0 confirmed)", "carry": None}
    return {"skip": False, "reason": "", "carry": None}


def rollup(host):
    p = os.path.join(_root(), "targets", f"{host}.json")
    return json.load(open(p)) if os.path.exists(p) else None


def gc(action="report", max_mb=10, keep=KEEP, root=None):
    """report | rotate | purge-backups over every *.jsonl in the ledger dir."""
    base = root or _root()
    rows = []
    for dirpath, _dirs, names in os.walk(base):
        for n in sorted(names):
            if not n.endswith(".jsonl"):
                continue
            live = os.path.join(dirpath, n)
            backups = [f"{live}.{i}" for i in range(1, keep + 1) if os.path.exists(f"{live}.{i}")]
            live_sz = os.path.getsize(live) if os.path.exists(live) else 0
            total = live_sz + sum(os.path.getsize(b) for b in backups)
            if action == "rotate" and live_sz >= max_mb * 1024 * 1024:
                _rotate_if_needed(live, max_bytes=max_mb * 1024 * 1024, keep=keep)
            if action == "purge-backups":
                for b in backups:
                    os.remove(b)
            rows.append({"file": live, "live_bytes": live_sz, "total_bytes": total,
                         "backups": len(backups)})
    return rows


def _selftest():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    os.environ["BUGHUNTER_MEMORY_DIR"] = d
    try:
        f = {"url": "http://a.com/x", "param": "id", "vuln_class": "idor", "severity": "high"}
        assert record_finding("e1", "a.com", ["nextjs"], f, {"reason": "pii", "severity": "high"}) is True
        assert record_finding("e1", "a.com", ["nextjs"], f, {"reason": "pii"}) is False   # dedup
        record_run("e1", ["nextjs"], ["http://a.com/y|q|xss", "http://a.com/x|id|idor"],
                   [{"url": "http://a.com/x", "vuln_class": "idor"}])
        negs = _read(os.path.join(d, "negatives.jsonl"))
        assert any(n["vuln_class"] == "xss" for n in negs)          # xss tested, not confirmed -> negative
        assert not any(n["vuln_class"] == "idor" for n in negs)     # idor confirmed -> no negative
        assert json.load(open(os.path.join(d, "targets", "a.com.json")))["sessions"] == 1
        # skip_decision: known-confirmed carries the finding
        skip_res = skip_decision("a.com", ["nextjs"], {"url": "http://a.com/x", "param": "id", "vuln_class": "idor"})
        assert skip_res["skip"] and skip_res["reason"] == "known-confirmed" and skip_res["carry"]["verdict"]["real"] is True
        # unseen class is never skipped
        assert skip_decision("a.com", ["nextjs"], {"url": "http://a.com/x", "param": "id", "vuln_class": "rce"})["skip"] is False
        # dead-class only after >= threshold negatives with zero confirmations
        for index in range(DEAD_CLASS_THRESHOLD):
            record_run(f"e-{index}", ["django"], ["http://b.com/z|q|csrf"], [])
        assert skip_decision("b.com", ["django"], {"url": "http://b.com/z", "param": "q", "vuln_class": "csrf"})["skip"] is True
        # a confirmation on that (stack,class) revives it (not dead)
        record_finding("e", "b.com", ["django"], {"url": "http://b.com/z", "param": "q", "vuln_class": "csrf", "severity": "low"}, {"reason": "x"})
        assert skip_decision("b.com", ["django"], {"url": "http://b.com/z", "param": "q", "vuln_class": "csrf"})["reason"] == "known-confirmed"
        print("memory.py self-test: PASS")
    finally:
        shutil.rmtree(d)
        os.environ.pop("BUGHUNTER_MEMORY_DIR", None)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="autopilot ledger")
    ap.add_argument("--gc", action="store_true", help="run garbage-collection instead of the self-test")
    ap.add_argument("--rotate", action="store_true", help="with --gc: rotate files over the cap")
    ap.add_argument("--purge-backups", action="store_true", help="with --gc: delete all .1/.2/.3 backups")
    ap.add_argument("--dir", default=None, help="ledger dir (default ~/.claude/bughunter/memory)")
    ap.add_argument("--max-mb", type=int, default=10)
    a = ap.parse_args()
    if a.gc:
        act = "purge-backups" if a.purge_backups else ("rotate" if a.rotate else "report")
        for r in gc(act, a.max_mb, KEEP, a.dir):
            print(f"  {r['file']}: live={r['live_bytes']}B total={r['total_bytes']}B backups={r['backups']}")
    else:
        _selftest()
