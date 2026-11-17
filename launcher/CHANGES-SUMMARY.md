# Changes Summary — Claude-BugHunter Safe Upgrades

## 1. triage.md (major)

**Before:** 7 soft questions, relatively easy to pass.

**After:** Strict **8-Question Gate**
- Q1 now requires actual request + response body (not just “I can reproduce”)
- Q2 requires proof of real impact (data / action / privilege), not status codes
- New Q7 forces high-value class or real chain
- New Q8 requires clean reproducibility with current evidence
- Expanded instant-kill list
- Clearer DOWNGRADE vs KILL distinction

**Goal:** Kill weak findings earlier and protect validity ratio.

## 2. validate.md (major)

- Same 8-Question Gate enforced again
- Explicit high-severity extra requirements (two-account PoC preferred, real data for SSRF, etc.)
- Stronger “always-rejected unless chained” table
- 4 Gates made more concrete and evidence-focused

## 3. prioritize.md (new command)

Forces ranking of surface and findings by historical impact / payout potential instead of ease.

Order: Auth/ATO → IDOR+sensitive → SSRF internal → RCE → Business logic → strong XSS → everything else.

## 4. report.md (tightened)

- Mandatory scope confirmation block
- Impact-first writing enforced
- Soft language banned
- Stronger evidence expectations before generating the report
- Platform-specific structure kept but cleaned

## 5. high-severity-focus.md (new skill)

System prompt bias so the AI defaults to the classes that actually matter and pay.

## 6. Launcher (index.html)

Provided in `launcher-patches.js`:

- Engagement model upgraded to v2: status (active/hunting/validated/reported/killed), priority, notes, kill reason
- One-click status cycling
- Strict 8-question triage UI + matching `triageGate()` logic
- Improved report draft with scope field and better templates
- Migration path from old localStorage key

## How to apply

### Commands & Skill
Copy the four `.md` files from `commands/` and the skill into your Claude-BugHunter install (or `~/.claude/commands/` / skills directory).

### Launcher
1. Open `index.html`
2. Replace the engagement functions (`getEngs`, `setEngs`, `renderEngs`, start handler) with the versions in `launcher-patches.js`
3. Replace `toolTriageHTML`, `triageGate`, `toolReportHTML`, and `reportDraft` with the new versions
4. Update the `wireTool` handlers for triage and report as shown in the comment block at the bottom of the patch file
5. Change `LS_ENG` to `"cbh_engagements_v2"` (already done in the patch)

After that the in-browser tools match the stricter markdown commands.
