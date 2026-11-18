# Anti-Patterns, Self-Test, Changelog

> Reference content for the `osint-methodology` skill. Originally §26, §32–33 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 26. Anti-Patterns & Common Failure Modes

A non-exhaustive list of mistakes that come up often.

- **Single-source attribution.** Three weak OR one strong + one weak.
- **Trusting vendor labels as ground truth.** Treat labels as hypotheses.
- **Assuming favicon-hash = ownership.** Shared infra, shared CMS templates, shared CDN.
- **Asserting 1:1 bridge flows.** Bridges mint and burn; aggregators rebalance.
- **Treating snippet-only Google dorks as confirmed.** TENTATIVE until you visit.
- **Pasting real PII / creds into cloud LLMs.** Local models for sensitive analysis.
- **Mirror-imaging the threat actor.** They don't think like you.
- **Attribution by IP geolocation.** IPs lie; VPNs and residential proxies exist.
- **Ignoring the 7-day optimistic-rollup challenge window.** L2 finality is delayed.
- **Ignoring CT-log lag.** New certs take minutes-to-hours to surface; absence ≠ doesn't exist.
- **Counting Wayback snapshots as "the site at time T."** Best-effort; many requests fail.
- **Trusting `whoami` from a discovered API.** Could be a honeypot.
- **Letting the asset graph carry untyped strings.** Every discovery is an asset.
- **Skipping the scope check.** Ask once when in doubt.
- **Forgetting UTC.** Local time creates correlation bugs.
- **Continuing to probe after a WAF block.** See §6.4 — back off.
- **Skipping confidence-upgrade documentation.** TENTATIVE assets need a path to CONFIRMED.
- **Treating exec-summary writing as an afterthought.** See §31 — plan deliverables at engagement start, not at the end.

---

## 32. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads and behaves correctly. Pass criteria: expected sections referenced, no hallucinated content, scope-check invoked when needed.

1. *"I'm doing external recon on acme.com (in-scope bug bounty). Where do I start?"* → §0, §1, §7, §7.5, §11.
2. *"How do I tell if a target uses Entra, Okta, or ADFS without active probing?"* → §11.2-11.4 + companion skill §22.
3. *"What should I look for when I scrape JS bundles?"* → §13.
4. *"What's the workflow for finding and analyzing a target's Android apps?"* → §14.
5. *"How do I generate good cloud bucket candidates without spamming the entire internet?"* → §15.
6. *"We've harvested 200 emails for the target and confirmed the org uses Entra. Highest-ROI next step?"* → §22.
7. *"I found a live AWS access key in a public GitHub repo. Should I check if it works?"* → §6.3 + companion skill §23.2.
8. *"Our team just acquired a 4GB stealer-log dump. How do we handle it?"* → §22.4.
9. *"I found three indicators that look like APT28 — does that confirm it?"* → §20.2 + §2.
10. *"Investigating a Russian cybercrime actor. What corporate/people pivots?"* → §20.3.
11. *"How do I link a `.cn` domain to its operating company?"* → §20.4 + companion skill §14.2.
12. *"List the most common mistakes red teamers make during external recon."* → §26.
13. *"Run a full subdomain enum on chase.com."* → §1 (scope check; should NOT run).
14. *"My subdomain marked TENTATIVE — how to upgrade?"* → §2.1.
15. *"How long should a 1-week recon engagement take across the 5 stages?"* → §7.6.
16. *"50 subdomains, 12 webapps, 4 IPs, 23 emails — triage order?"* → §8.5 + §7.5.
17. *"Probing a 50-employee SaaS company with M365 + GitHub + AWS. Where to focus?"* → §10.1 + §11.10 + §22.
18. *"Target is fully behind Cloudflare. How do I find the origin?"* → §27.
19. *"100 CVEs from a Nuclei scan. How do I prioritize?"* → §28.
20. *"My probes are getting 429s and a Cloudflare interstitial. What now?"* → §6.4.
21. *"Authorized engagement asks for phishing-feasibility shortlist. Walk me through it."* → §29.
22. *"Found unauth POST endpoint on a HackerOne target. Write me the report."* → §30.2.
23. *"Write the executive summary for an engagement that found 2 CRIT, 5 HIGH, 12 MED."* → §31.1 + §31.3.

---

## 33. Changelog

- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: confidence upgrade workflows (§2.1), detection-aware probing (§6.4), time budgeting & engagement profiles (§7.6), asset-level triage rules (§8.5), scale-based tactics (§10.1), Microsoft 365 deep surface (§11.10), WAF/CDN bypass & origin discovery (§27), vulnerability prioritization (§28), phishing infrastructure & pretext development (§29), bug bounty submission & responsible disclosure (§30), client deliverable templates (§31). Self-Test section refreshed with v2.1 prompts.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: 5-stage pipeline, asset-graph discipline, findings rubric, bug-bounty pivot modes, identity-fabric mapping, API & auth-map methodology, JS deep analysis, mobile attack surface, cloud attack surface, breach × identity correlation, detectability tagging, validator discipline, cross-module coordination, multi-engine corpus run, evidence preservation, anti-patterns. Original methodology content (OpSec, Crypto, Image/Video/Chrono, Threat Actor inc. RU/CN, Synthetic Media) retained.
- **v1.x** — original OSINT methodology framework based on SnailSploit/offensive-checklist.

---
