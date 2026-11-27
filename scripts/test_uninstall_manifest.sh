#!/usr/bin/env bash
# `install.sh --uninstall` must delete only manifest entries of the shape
# skills/<dir>, commands/<file>, scripts/<file>. Lines like `../precious`,
# `skills/`, `skills//`, `skills/.` must be skipped (with a warning) and delete
# nothing; a valid `skills/goner` is still removed. Runs in a temp HOME. Stdlib bash only.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="${INSTALL_SH:-$ROOT/scripts/install.sh}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home" ZDOTDIR="$T/home"
M="$HOME/.claude/.skill-manifests"
mkdir -p "$M" "$HOME/precious" "$HOME/.claude/skills/keep-a" "$HOME/.claude/skills/keep-b" "$HOME/.claude/skills/goner"
touch "$HOME/precious/data" "$HOME/.claude/skills/keep-a/SKILL.md" "$HOME/.claude/skills/keep-b/SKILL.md"
printf '%s\n' '../precious' 'skills/' 'skills//' 'skills/.' 'skills/..' 'skills/../..' '/etc/passwd' 'skills/a/b' 'skills/goner' > "$M/claude-bughunter.txt"

out="$(bash "$INSTALL" --uninstall 2>&1)"

fail=0
[ -f "$HOME/precious/data" ] || { echo "FAIL: ../precious was deleted"; fail=1; }
for k in keep-a keep-b; do
  [ -f "$HOME/.claude/skills/$k/SKILL.md" ] || { echo "FAIL: skills/$k was deleted"; fail=1; }
done
[ -d "$HOME/.claude/skills" ] || { echo "FAIL: skills/ itself was deleted"; fail=1; }
[ ! -e "$HOME/.claude/skills/goner" ] || { echo "FAIL: valid skills/goner was not removed"; fail=1; }
case "$out" in *"skipping unsafe manifest entry: ../precious"*) ;; *) echo "FAIL: no warning for ../precious"; fail=1 ;; esac
case "$out" in *"removed 1 item(s); kept 0"*) ;; *) echo "FAIL: counts wrong (want removed 1, kept 0)"; fail=1 ;; esac

# a CRLF manifest line must still resolve to its entry (trailing CR stripped)
mkdir -p "$HOME/.claude/skills/goner-crlf" "$M"
printf '%s\r\n' 'skills/goner-crlf' > "$M/claude-bughunter.txt"
bash "$INSTALL" --uninstall >/dev/null 2>&1
[ ! -e "$HOME/.claude/skills/goner-crlf" ] || { echo "FAIL: CRLF manifest entry was not removed"; fail=1; }

if [ "$fail" -eq 0 ]; then echo "PASS: uninstall skips unsafe manifest entries"; fi
exit "$fail"
