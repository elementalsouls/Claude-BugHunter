#!/usr/bin/env python3
"""attack_metrics.py — per-operator, generic-fingerprint attack metrics.

**Leak-proof by construction.** The store holds ONLY integer/float counters
keyed by generic tokens — `stack_sig` (tech fingerprint), `vuln_class`,
`technique` (a generic category). It NEVER stores a host, URL, path, param
value, payload, response body, or free-text reason. There is no engagement or
host field. Two engagements on the same stack aggregate into the same counters,
so nothing target-identifying can be recovered.

Opt-in, default-off (engine `--use-metrics`). Store is git-ignored, plaintext
JSON (auditable), per-operator.

Store: ~/.claude/bughunter/attack-metrics/metrics.json
       (override BUGHUNTER_METRICS_DIR)
Row (value) shape, keyed by "stack_sig\\x1fvuln_class\\x1ftechnique":
  {"attempts":N, "successes":M, "cost_total":F, "exec_count":N, "updated":"<ts>"}

Ranking is advisory only: rank() orders hypotheses by recorded hit-rate for the
human operator. It never fires a request, never bypasses scope, the
corroborator, or the 7-Question gate.
"""
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

SCHEMA = 1
SEP = "\x1f"  # unit separator — not valid in any of our generic tokens

# --- fail-closed allowlist: reject anything target-shaped ---
# a generic token never contains a scheme, path, query, host port, IP, or space.
_BAD_CHARS = set("/:@?#=&%<> \t\n\r\"'\\")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CLASS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_TECHNIQUE_RE = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,59}$")
_STACK_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,39}$")


def _root():
    return os.path.expanduser(os.environ.get(
        "BUGHUNTER_METRICS_DIR", "~/.claude/bughunter/attack-metrics"))


def _path():
    root = _root()
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "metrics.json")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generic(tok, kind):
    """True iff `tok` is a safe generic token (no target data). Fail-closed."""
    if not tok or len(tok) > 60:
        return False
    if any(c in _BAD_CHARS for c in tok):
        return False
    if _IPV4.match(tok):
        return False
    if kind == "class":
        return bool(_CLASS_RE.match(tok))
    if kind == "technique":
        return bool(_TECHNIQUE_RE.match(tok))
    if kind == "stack":
        # pipe-joined tech tokens; each must look like a tech name, not a host.
        # A multi-label host (api.victim.co.uk) has >=2 dots -> rejected; a
        # single-dot tech token (asp.net, node.js) is allowed.
        for t in tok.split("|"):
            if not _STACK_TOKEN_RE.match(t) or t.count(".") >= 2 or _IPV4.match(t):
                return False
        return True
    return False


def _stack_sig(tech_stack):
    return "|".join(sorted({t.lower() for t in (tech_stack or []) if t}))


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        d = json.load(open(path, encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def update(stack_sig, vuln_class, attempts=0, successes=0, cost=0.0, technique=""):
    """Add counters to one (stack_sig, vuln_class, technique) cell. Returns True
    if written, False (fail-closed, nothing written) if any key is not generic."""
    technique = technique or "none"
    if not (_generic(stack_sig, "stack") and _generic(vuln_class, "class")
            and _generic(technique, "technique")):
        print(f"attack_metrics: refused non-generic key "
              f"(stack/class/technique) — nothing written", file=sys.stderr)
        return False
    path = _path()
    lock = path + ".lock"
    lfd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        if fcntl:
            fcntl.flock(lfd, fcntl.LOCK_EX)
        data = _load(path)
        key = SEP.join((stack_sig, vuln_class, technique))
        cell = data.get(key) or {"attempts": 0, "successes": 0,
                                  "cost_total": 0.0, "exec_count": 0}
        cell["attempts"] += int(attempts)
        cell["successes"] += int(successes)
        cell["cost_total"] = round(cell["cost_total"] + float(cost), 6)
        cell["exec_count"] += 1
        cell["updated"] = _now()
        data[key] = cell
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"schema": SCHEMA, **{k: v for k, v in data.items() if k != "schema"}},
                      f, indent=1, sort_keys=True)
        os.replace(tmp, path)
        return True
    finally:
        if fcntl:
            fcntl.flock(lfd, fcntl.LOCK_UN)
        os.close(lfd)


def update_from_run(stack_sig, tested_keys, confirmed, cost_total=0.0):
    """Aggregate a run into metrics BY CLASS ONLY — never a host/url. tested_keys
    are the engine's 'url|param|class' strings; only the class tail is used."""
    tried = Counter(k.rsplit("|", 1)[-1] for k in tested_keys if k.rsplit("|", 1)[-1])
    won = Counter(f.get("vuln_class", "") for f in confirmed if f.get("vuln_class"))
    n = sum(tried.values()) or 1
    for cls, attempts in tried.items():
        update(stack_sig, cls, attempts=attempts, successes=won.get(cls, 0),
               cost=cost_total * attempts / n)


def rank(stack_sig, min_attempts=1):
    """Advisory ranking of (vuln_class, technique) for this stack by hit-rate.
    Read-only: returns hypotheses for the human; fires nothing."""
    data = _load(_path())
    rows = []
    for key, cell in data.items():
        if key == "schema" or not isinstance(cell, dict):
            continue
        parts = key.split(SEP)
        if len(parts) != 3 or parts[0] != stack_sig:
            continue
        attempts = cell.get("attempts", 0)
        if attempts < min_attempts:
            continue
        rows.append({
            "vuln_class": parts[1], "technique": parts[2],
            "attempts": attempts, "successes": cell.get("successes", 0),
            "hit_rate": round(cell.get("successes", 0) / attempts, 4) if attempts else 0.0,
            "cost_total": cell.get("cost_total", 0.0), "updated": cell.get("updated", ""),
        })
    rows.sort(key=lambda r: (-r["hit_rate"], -r["attempts"], r["vuln_class"]))
    return rows


def _selftest():
    import tempfile
    d = tempfile.mkdtemp()
    os.environ["BUGHUNTER_METRICS_DIR"] = d
    try:
        assert update("django|nginx", "idor", attempts=4, successes=2) is True
        assert update("victim.example.com", "idor", attempts=1) is False  # host rejected
        assert update("django", "GET /x", attempts=1) is False            # payload rejected
        blob = open(os.path.join(d, "metrics.json"), encoding="utf-8").read()
        assert "http" not in blob and "/" not in blob and "victim" not in blob
        assert rank("django|nginx")[0]["hit_rate"] == 0.5
        print("attack_metrics self-test: PASS")
    finally:
        import shutil
        shutil.rmtree(d)
        os.environ.pop("BUGHUNTER_METRICS_DIR", None)


if __name__ == "__main__":
    _selftest()
