#!/usr/bin/env bash
# #252: `hunt` must reject a target name that would escape or nest outside
# $HUNT_BASE (`../escaped`, `a/b/c`, `-x`, `.hidden`) and create nothing; a
# normal name (`acme.example_1`) must still scaffold. Stdlib bash only.
set -u
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HUNT_BASE="$T/targets"
# shellcheck disable=SC1090
. "$(dirname "$0")/hunt.sh"

fail=0
for bad in "../escaped" "a/b/c" "-x" ".hidden"; do
  hunt "$bad" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then echo "FAIL: hunt '$bad' returned 0 (should reject)"; fail=1; fi
done
# no directory may have been created anywhere under $T by the bad names
created="$(find "$T" -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
if [ "$created" != "0" ]; then
  echo "FAIL: bad target names created $created dir(s):"; find "$T" -mindepth 1 -type d; fail=1
fi

# a clean name still works
hunt "acme.example_1" >/dev/null 2>&1
if [ ! -d "$HUNT_BASE/acme.example_1/findings" ]; then
  echo "FAIL: clean target 'acme.example_1' did not scaffold"; fail=1
fi

if [ "$fail" -eq 0 ]; then echo "PASS: hunt target-name validation (#252)"; fi
exit "$fail"
