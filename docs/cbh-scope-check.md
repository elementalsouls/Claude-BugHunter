# Scope check CLI

`cbh scope check` checks one or more hosts or URLs against the same deterministic scope rules used by the engagement engine. It is a useful preflight before running recon or investigating a candidate: explicit out-of-scope rules take precedence, and unmatched targets are denied by default.

```bash
# From a repository clone (or with scripts/cbh.py symlinked as cbh)
cbh scope check --md scope.md https://app.example.com https://third-party.example.net

# JSON scope files are also supported
cbh scope check --scope-file engagement/scope.json api.example.com admin.example.com
```

The command prints an `IN-SCOPE` or `OUT-OF-SCOPE` verdict for each target. It exits `0` only when every target is in scope, `1` when at least one target is denied, and `2` for usage or scope-loading errors. The markdown parser and matching behavior are shared with `engine/scope.py`; the command is clone-mode only and does not make network requests.
