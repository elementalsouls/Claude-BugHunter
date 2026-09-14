# People, Username, Phone, Social, Public Records OSINT

> Reference content for the `offensive-osint` skill. Originally §7 + §8 + §9 + §10 + §13 + §14 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 7. Search Engines

| Tool | Notes |
|------|-------|
| [Carrot2](https://search.carrot2.org/#/search/web) | Clusters results by topic |
| [etools](https://www.etools.ch/) | Metasearch |
| [Kagi](https://kagi.com/) | Privacy-first, non-personalized |
| [Brave Search](https://search.brave.com/) | Independent index; Goggles for custom ranking |
| [PDF Search](https://www.pdfsearch.io/) | PDF + table of contents |
| [Google Fact Check Explorer](https://toolbox.google.com/factcheck/explorer) | Cross-site fact-check |

---

## 8. Username & Email Investigation

| Tool | Purpose |
|------|---------|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across social networks |
| [Maigret](https://github.com/soxoj/maigret) | Profile collector by username |
| [What's My Name](https://whatsmyname.app/) | Username search |
| [Holehe](https://github.com/megadose/holehe) | Email registration check |
| [Epieos](https://epieos.com/) | Email pivots and metadata |
| [OSINT Industries](https://osint.industries/) | Email/username/phone lookups |
| [Hunter.io](https://hunter.io/) | Domain → emails |
| [EmailRep](https://emailrep.io/) | Email reputation |
| [Emailable](https://emailable.com/) | Email verification |
| [Mugetsu](https://mugetsu.io/) | X/Twitter username history |
| [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) | Email enrichment + pattern guessing |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Phone number intelligence |

Browser extensions: [GetProspect](https://chromewebstore.google.com/detail/email-finder-getprospect/bhbcbkonalnjkflmdkdodieehnmmeknp), [SignalHire](https://chrome.google.com/webstore/detail/signalhire-find-email-or/aeidadjdhppdffggfgjpanbafaedankd).

---

## 9. People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [Clearbit](https://clearbit.com/) — company/individual data enrichment.
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.
- [Face2social](https://face2social.com/) — reverse face search limited to public social media profile pictures (Instagram, Facebook, TikTok, X); does not crawl the open web, so PimEyes and FaceCheck.ID beat it on general web coverage. Free preview without sign-up, paid plans beyond it; U.S. only.

---

## 10. Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).
- [NumlookupAPI](https://numlookupapi.com/) [Freemium] — programmatic carrier checks.
- [CallerIDTest](https://calleridtest.com/), [Advanced Background Checks](https://www.advancedbackgroundchecks.com/).

---


## 13. Social Media

| Platform | Tool |
|----------|------|
| Instagram | [Picuki](https://www.picuki.com/) — profile view without account |
| X/Twitter | [snscrape](https://github.com/snscrape/snscrape) — preferred CLI scraper; Twint as fallback |
| Facebook | [Graph Search](https://inteltechniques.com/tools/Facebook.html), [sowsearch.info](https://sowsearch.info/), [lookup-id.com](https://lookup-id.com/), [whopostedwhat.com](https://whopostedwhat.com/) |
| Facebook (research) | [Meta Content Library](https://transparency.meta.com/researcher) — CrowdTangle successor (researcher-gated) |
| YouTube/Twitch | [Social Blade](https://socialblade.com/) — analytics |
| TikTok | [Tokboard](https://tokboard.com/) — trends + profile analytics |
| Reddit | [Reveddit](https://www.reveddit.com/) — removed content; [RedTrack.social](https://redtrack.social/) — user history |
| Bluesky | [Firesky](https://firesky.tv/) — real-time firehose; [SkyView](https://bsky.jazco.dev/) — follower graphs |
| Mastodon | [FediSearch](https://fedisearch.skorpil.cz/) — cross-instance search; [Fedifinder](https://fedifinder.glitch.me/) — find Twitter users on Mastodon |
| Faces | [Search4Faces](https://search4faces.com/) |

---

## 14. Public Records & Company Information

- [OpenCorporates](https://opencorporates.com/) — world's largest open company DB.
- [SEC EDGAR](https://www.sec.gov/edgar.shtml) — U.S. company filings.
- [OpenOwnership Register](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA repository + request tracking.
- [EU Tenders (TED)](https://ted.europa.eu/) — EU procurement notices.
- [World Bank Projects](https://projects.worldbank.org/) — project + procurement records.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/) — UK companies + officers + filings.

### 14.1 RU registries

[Rusprofile](https://www.rusprofile.ru/), [Kontur.Focus](https://focus.kontur.ru/) (freemium), [zakupki.gov.ru](https://zakupki.gov.ru/) (procurement), EGRUL/EGRIP (official, captcha-gated).

### 14.2 CN registries + USCC + ICP

- **GSXT** — [gsxt.gov.cn](https://www.gsxt.gov.cn/) National Enterprise Credit Info; cross-check with Tianyancha / Qichacha.
- **USCC (Unified Social Credit Code)** — 18-character entity ID assigned to all CN legal entities. Format: `<region:6><authority:2><type:1><serial:9>`. Useful for joining GSXT records to ICP filings.
- **ICP Beian** — [beian.miit.gov.cn](https://beian.miit.gov.cn/) — every domain serving traffic in mainland CN must register an ICP filing; the filing links the domain to a USCC, which links to the legal entity in GSXT.
- Workflow: `target.cn` domain → ICP lookup → USCC → GSXT → entity name + officers + adjacent registered entities.

### 14.3 Sanctions & Compliance

- [OFAC SDN List](https://sanctionssearch.ofac.treas.gov/), [EU Sanctions Map](https://www.sanctionsmap.eu/).
- [OpenSanctions](https://www.opensanctions.org/) — aggregated.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative documents, leaks, company records.

---

