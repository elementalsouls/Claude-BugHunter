---
name: web3-audit
description: Smart contract security audit — 10 DeFi bug classes (accounting desync, access control, incomplete path, off-by-one, oracle, ERC4626, reentrancy, flash loan, signature replay, proxy), pre-dive kill signals (TVL < $500K etc), Foundry PoC template, grep patterns for each class, and real Immunefi paid examples. Use for any Solidity/Rust contract audit or when deciding whether a DeFi target is worth hunting.
sources: public_research, community
---

# WEB3 SMART CONTRACT AUDIT

10 bug classes. Pre-dive kill signals. Foundry PoC template. Real paid examples.

> **Layout** — Refactored 2026-11-18 from a 601-line monolith into a lean SKILL.md plus 5 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## PRE-DIVE KILL SIGNALS (check BEFORE any code review)

> ZKsync lesson: $322M TVL + OZ audit + 750K LOC + 5 sessions = 0 findings. Large well-audited bridges are extremely hard.

1. **TVL < $500K** → max payout capped too low for effort
2. **2+ top-tier audits** (Halborn, ToB, Cyfrin, OpenZeppelin) on simple protocol → bugs already found
3. **Protocol < 500 lines, single A→B→C flow** → minimal attack surface
4. **Formula**: `max_realistic_payout = min(10% × TVL, program_cap)` — if < $10K, skip

**Soft kill:** OZ/ToB/Cyfrin audit on current version + codebase > 500K LOC → expect 40+ hours for maybe 1 finding. Only proceed if bounty floor > $50K AND you have protocol-specific expertise.

**Target scoring (go if >= 6/10):**
- TVL > $10M: +2
- Immunefi program with Critical >= $50K: +2
- No top-tier audit on current version: +2
- < 30 days since deploy: +1
- Protocol you've hunted before: +1
- Source code + natspec comments: +1
- Upgradeable proxies: +1

---

## THE ONE RULE

> "Read ALL sibling functions. If `vote()` has a modifier, check `poke()`, `reset()`, `harvest()`. The missing modifier on the sibling IS the bug."

This single rule explains 19% of all Critical findings.

---

## How to use this skill

This skill is a **lean audit orchestrator**. Detail content lives in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md for pre-dive kill signals, THE ONE RULE, and operator notes.
2. For the current task, **read only the reference file(s) you need** — do NOT pull all 5.
3. Immunefi submissions need a Foundry PoC — load `foundry.md` before writing the report.

**Loading rules of thumb:**

- Accounting desync / missing sibling modifier → `accounting-access.md`
- Function-family reverse / off-by-one → `path-boundary.md`
- Oracle staleness / ERC4626 inflation → `oracle-vault.md`
- Reentrancy / flash loan / signature replay / proxy → `reentrancy-proxy.md`
- Foundry test skeleton → `foundry.md`

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `accounting-access.md` | Phantom yield, early-return desync, missing sibling modifier, silent modifier, uninit proxy | accounting desync, poke(), onlyAdmin, initialize |
| `path-boundary.md` | Missing refund, mint vs deposit, > vs >= at period/array/amount boundaries | incomplete path, off-by-one, ThunderNFT |
| `oracle-vault.md` | Chainlink staleness, Pyth conf, short TWAP, ERC4626 inflation / transfer lock | oracle, Chainlink, Pyth, ERC4626 |
| `reentrancy-proxy.md` | CEI, flash-loan oracle, nonce/chainId, storage collision, UUPS init | reentrancy, flash loan, ecrecover, UUPS |
| `foundry.md` | ExploitTest skeleton, cheatcodes, forge test / fork / coverage | Foundry, forge test, vm.prank |

## Related Skills & Chains

- **`meme-coin-audit`** — When the target is a meme coin / SPL token rather than a DeFi protocol. Workflow primitive: pre-dive kill signals diverge — this skill's "TVL < $500K skip" doesn't apply to meme coins where the rug check (mint authority, freeze authority, LP lock) is the entire audit; route to `meme-coin-audit` instead.
- **`triage-validation`** — When a contract finding is ready to be filed on Immunefi. Workflow primitive: Immunefi has its own report format, but the impact-validated, chain-end-to-end discipline of `triage-validation` still applies; run the 7Q gate against the Foundry PoC before submitting.
- **`report-writing`** — When writing the Immunefi report body. Workflow primitive: `report-writing`'s Immunefi template (with Foundry PoC, root cause code snippet, quantified economic impact) is the body skeleton this skill's findings feed into.
- **`offensive-osint`** — When auditing a protocol's off-chain attack surface (frontend, admin API, RPC gateways). Workflow primitive: on-chain audit is this skill's job; any web2 component of the protocol (web-frontend, admin panel, indexer API) routes to `offensive-osint` for recon.
- **`bb-methodology`** — When deciding whether to dive at all. Workflow primitive: PART 0 of `bb-methodology` confirms engagement (web3 bug bounty / private audit / smart-contract review); this skill's pre-dive kill signals replace the standard scoring rubric for that engagement type.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream content covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Bug classes still paying in 2026

Flash-loan attacks remain top-paid on Immunefi (top 5 in 2024-2026 by bounty). The economic primitive — borrow $50M, manipulate price oracle, drain pool, repay — keeps reappearing because new protocols keep shipping with composability assumptions that don't hold under flash-loaned imbalance.

Reentrancy IS still paying because new protocols keep shipping with ERC-777 / hooks / callbacks. Don't assume the class is dead — the 2023-2025 paid corpus contains 40+ reentrancy bugs against post-Checks-Effects-Interactions codebases (cross-function reentrancy, read-only reentrancy via view functions called during state-mid-flight).

Oracle manipulation: still paid heavily but harder. Most projects use Chainlink price feeds now; the attack target is the SECONDARY oracle most projects also use (TWAP from a low-liquidity Uniswap V2 pair, the protocol's own internal oracle, a stale fallback path). Audit the failover chain, not just the primary feed.

### What's new since the vendored content was written

- **EIP-1153 (transient storage)** — introduced in 2024. New reentrancy classes: transient-storage reads cached across the same transaction can desync from persistent storage. Audit any `tload`/`tstore` usage for read-after-external-call.
- **EIP-7702 (Pectra hard fork 2025)** — added EOA-to-smart-account upgrades. New ATO-like primitives via re-delegation: an EOA signed-once can delegate to a contract that the attacker controls, then signature replay across delegations.
- **Account abstraction (ERC-4337 bundlers)** — paymaster sponsorship abuse and bundler griefing. Paymaster contracts that don't enforce strict sender allowlists drain on first call.
- **ZK-rollup bridge bugs** — proof-replay across rollups, off-chain prover compromise, sequencer censorship leading to forced-inclusion edge cases.
- **LST/LRT depeg dynamics** — liquid-staking and liquid-restaking tokens that assume 1:1 peg under loss conditions; oracle assumes peg, market reflects depeg, liquidation logic breaks.

### Tool stack for 2026

Foundry remains the test framework. `forge test --gas-report --debug` for invariant testing; `forge fuzz` for property-based testing; `forge inspect` for storage-layout audits. Slither + Echidna for static + fuzz. Mythril for symbolic execution on smaller contracts. tenderly.co for forking + simulation (best UX for replicating attacks against mainnet state).

For Solana: anchor framework, sealevel-attacks corpus (curated PoCs by anchor maintainers), soteria-sec / sec3 scanner. For Move (Aptos, Sui): move-prover, aptos-cli `aptos move test`.

For cross-chain: hyperlane and LayerZero each have audit-tooling repos; bridge bugs require simulating both endpoints, not just one.

### Where pre-dive kill signals matter

TVL under $500K isn't worth the audit time unless the bounty floor is high. Audit firm already covered it = low ROI unless you find what they missed — look at the audit-report scope-exclusion section for what they EXPLICITLY didn't audit (oracles, governance, off-chain components, frontend, the admin path).

Multisig signers > 5 + timelock > 48h = low rug-pull risk; if your finding requires team-malicious assumptions, it's low-impact and likely out of scope per Immunefi's "centralization risk" exclusion. Read the program brief — most Immunefi programs explicitly downgrade or reject findings that assume admin malice.

### Reporting discipline

Immunefi requires Foundry PoC. Submission without PoC is auto-rejected. Submission with a PoC that requires manual setup ("first deploy this, then call that") usually gets downgraded — the PoC should be a single `forge test` invocation that proves the impact, with explicit `assertEq` on the drained balance / minted token / corrupted state.

Severity claims must use Immunefi's severity matrix exactly; don't invent severities. The matrix gates on direct economic loss percentage of TVL — a critical against a $500K protocol pays differently than a critical against a $500M one. Read the program's specific severity assignment before claiming Critical.
