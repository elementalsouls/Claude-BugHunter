# hunt-saml — Pattern Library

> Patterns and verifiable public examples behind `hunt-saml`. Operator-grade reference, not a complete enumeration. Cited examples here are academic research, CVE entries, and widely-discussed industry classes any reader can search and verify; uncited patterns are general operator knowledge derived from public SAML library advisories, OASIS specifications, and conference research.

SAML attacks pay top-tier bounties because a single forged assertion silently impersonates any user in the directory — typically including administrators — and SP-side authorization frequently treats the post-SSO session as fully trusted. The bug almost never lives in the cryptography itself; it lives in the parser disagreement between the signature verifier and the application logic that subsequently *reads* the document. The patterns below cluster around the primitives that recur in real disclosures: XML Signature Wrapping, signature stripping, comment injection, missing audience/recipient checks, key trust over-acceptance, and replay windows. Every entry includes the exact XML manipulation because SAML is inert text on the wire, and the bug is usually one element-move or one attribute-flip.

## Cited Public Examples

### XML Signature Wrapping research — Juraj Somorovsky et al. (Ruhr-University Bochum)
- **Source:** Academic research from Ruhr-University Bochum's Chair for Network and Data Security, beginning with the 2012 paper "On Breaking SAML: Be Whoever You Want to Be" (Somorovsky, Mayer, Schwenk, Kampmann, Jensen — USENIX Security '12). Subsequent work catalogues eight XSW variants and demonstrates them against major SAML frameworks. Verifiable via the paper and the SAML Raider Burp extension that implements the variants.
- **Pattern shape:** Attacker takes a legitimately signed `<Response>` or `<Assertion>` and relocates the signed element while injecting a forged Assertion the application logic reads first. The signature still verifies because the verifier locates its referenced element by ID, but the application reads a different element by document position.
- **Key trick:** Eight catalogued variants (XSW1–XSW8) differ in where the wrapper element is placed and how the parser walks the tree to extract NameID and AttributeStatement.
- **Why it matters:** The canonical SAML bug class. Every SAML library has had at least one XSW-related CVE; variants keep working because library authors fix one path but not all eight. SAML Raider workflow (cycle through XSW1–XSW8) is mandatory bench work.

### Comment injection in NameID (industry class, 2018)
- **Source:** Coordinated disclosure across SAML libraries in February 2018 — Duo Security's "Duo Finds SAML Vulnerabilities Affecting Multiple Implementations" advisory and CVE-2018-0489 (Shibboleth), CVE-2017-11427 (OneLogin python-saml), CVE-2017-11428 (OneLogin ruby-saml). Cite the class — many CVEs landed in one wave because the root cause was identical across libraries.
- **Pattern shape:** Signature is computed over canonicalized XML which preserves text-node values across comments. The application code that later reads `NameID` uses a different DOM-walking primitive that returns only the first text node, *stopping at the comment*. So `<NameID>admin@target.com<!---->@attacker.com</NameID>` signs over the full string but the SP reads only `admin@target.com`.
- **Key trick:** An empty `<!---->` is enough to split the text-node stream. Fails when both signer and reader use the same canonicalization, but signer and downstream getNameID() frequently disagree.
- **Why it matters:** Pure parser disagreement, no signature break required. Pivots to any user whose NameID prefix the attacker can craft.

### CVE-2023-40337 — Citrix ADC / Gateway SAML logout assertion handling
- **Source:** NVD CVE-2023-40337 and Citrix advisory CTX583755. Citrix ADC / Gateway when configured as SAML SP processed assertion fields during logout in a way that allowed an authenticated attacker to escalate privileges. Verifiable through Citrix's security bulletin and the NVD entry.
- **Pattern shape:** Logout endpoints frequently re-parse assertion data without re-running all the validation that the login path does — recipient, audience, replay. An attacker producing any valid assertion targeted at the SP can manipulate logout-related claims to alter session state.
- **Key trick:** Login-path SAML validators get scrutiny; logout-path / reauth-path validators do not. Test every endpoint that accepts `SAMLResponse` or `SAMLRequest`, not just the AssertionConsumerService.
- **Why it matters:** SAML attack surface is anywhere the assertion is parsed. Code paths beyond `/saml/acs` are routinely under-validated.

### OWASP SAML Security Cheat Sheet
- **Source:** OWASP SAML Security Cheat Sheet, available at cheatsheetseries.owasp.org. Enumerates every validation step a SAML SP must perform: signature verification, issuer check, recipient check, audience restriction, NotBefore / NotOnOrAfter, replay protection, subject confirmation method.
- **Pattern shape:** The cheat sheet is a checklist. For each item, ask: "does this SP enforce it?" Each unenforced item is at least one bug class.
- **Key trick:** Read the cheat sheet as an inverted bug list. Every "MUST" is a recurring bug somewhere.
- **Why it matters:** Authoritative reference. When writing a report, citing the specific OWASP recommendation that was violated short-circuits a lot of triage debate.

## Disclosed HackerOne Reports (bounty-paid examples)

Bounty-paid public disclosures for this class, on top of the research/CVE grounding above. Targets genericized; each links its source.

### Signature verification bypass / XSW → auth as any user (disclosed bounty examples)
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/223014>, <https://hackerone.com/reports/2579939>, <https://hackerone.com/reports/136169>).
- **Pattern shape:** The SP accepts an assertion whose signature isn't properly validated — unsigned assertion, signature over the wrong element (XSW), or bypassed verification — so an attacker forges the `NameID` and logs in as anyone.
- **Key trick:** Capture a valid SAMLResponse, then: strip the signature, wrap the signed element and inject a forged assertion (XSW), or swap the `NameID`. Any accepted variant = full auth bypass.
- **Why it matters:** Authenticate as arbitrary users including admins; enterprise-critical, consistently four-to-five figures.

### RelayState / ACS URL validation → ATO / open redirect
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/1923672>, <https://hackerone.com/reports/2101076>).
- **Pattern shape:** Insufficient validation of RelayState or the ACS/return URL lets an attacker redirect the authenticated flow to a controlled endpoint or bind SSO to an attacker-chosen account.
- **Key trick:** Tamper RelayState and the ACS URL; check whether the assertion or session lands on an attacker origin. Chain with signup domain-enforcement bypass where SSO auto-provisions accounts.
- **Why it matters:** Captures the SSO assertion or hijacks provisioning → ATO across the SSO-federated surface.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/171398>

---

## Pattern Library

### XSW1 — sibling injection above signature
- **When to suspect:** SP accepts SAML responses signed by a legitimate IdP and reads NameID / AttributeStatement from the assertion. You have a valid login.
- **Test:** Capture your own legitimate SAML response. In SAML Raider, apply "XSW1." Manually: clone the existing signed `<Assertion>`, change `NameID` to `admin@target.com` in the clone, set the clone's `ID` to a new value, insert the clone as a sibling of the original `<Assertion>` *before* the signed element. Leave the signature pointing at the original `Assertion` ID.
  ```xml
  <samlp:Response>
    <saml:Assertion ID="evil">
      <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
      <saml:AttributeStatement>
        <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
    <saml:Assertion ID="legit-original">
      <saml:Subject><saml:NameID>you@target.com</saml:NameID></saml:Subject>
      <ds:Signature>...covers ID=legit-original...</ds:Signature>
    </saml:Assertion>
  </samlp:Response>
  ```
- **Validation:** Re-encode (base64 only — not base64+gzip unless the original was), URL-encode, POST to `/saml/acs`. If the SP logs you in as `admin@target.com` while the signature library reports the response as signed, XSW1 lands. Use a uniquely-marked admin test account if possible; otherwise check a NameID whose existence in the directory you can verify.
- **Pay-grade rationale:** Critical. ATO of any user including administrators.

### XSW2–XSW8 — variant placements
- **When to suspect:** XSW1 doesn't land. Different libraries traverse the document differently — first-Assertion, last-Assertion, depth-first, breadth-first.
- **Test:** SAML Raider provides one-click variants. Manually: place the evil assertion (a) inside the `<Extensions>` of the original Response, (b) wrapped inside the original signed Assertion's `Object` element, (c) wrapped *around* the original signed Assertion as the parent, (d) as a sibling below the signature, etc. Each variant exists because some parser walks the DOM in that specific order.
- **Validation:** Same as XSW1 — SP logs you in as the forged NameID while signature verification reports success.
- **Pay-grade rationale:** Critical.

### Comment injection in NameID
- **When to suspect:** Library version pre-2018 patch, or a custom SAML implementation that uses `node.textContent` / `getTextContent()` to extract NameID after signature validation.
- **Test:** Modify the NameID in your legitimate SAML response (without re-signing):
  ```xml
  <saml:NameID>admin@target.com<!---->@attacker.com</saml:NameID>
  ```
  The signature was computed over the original NameID, but if you can re-sign with your own valid IdP keypair (because you control your own legitimate SAML flow), use comment injection inside *your own* NameID. The canonicalized form `admin@target.com@attacker.com` is what signs; the SP's reader may stop at the comment and see `admin@target.com`.
- **Validation:** SP recognizes you as `admin@target.com`. Look at session cookie payload, `/api/me`, response headers.
- **Pay-grade rationale:** Critical when reachable. ATO of any user whose NameID local-part you can craft.

### Signature stripping — no signature accepted
- **When to suspect:** Custom SAML implementation, or an SP that reports "signed by IdP" but you suspect it never checks signature presence.
- **Test:** Take your legitimate SAML response, delete the entire `<ds:Signature>` element, change NameID to a victim, re-encode, submit.
  ```bash
  base64 -d <<< "$SAML" | xmllint --format - > saml.xml
  # delete <ds:Signature>...</ds:Signature>
  # change NameID
  cat saml.xml | base64 -w0
  ```
- **Validation:** SP accepts the unsigned assertion as logged-in user.
- **Pay-grade rationale:** Critical. Even rarer than XSW but devastating when it lands.

### Response signed but Assertion not — signature on wrong element
- **When to suspect:** SP claims "responses are signed." Inspect the signature reference URI — does it cover the `<samlp:Response>` element, or the `<saml:Assertion>` element?
- **Test:** When only the Response is signed (not the inner Assertion), inject an additional unsigned Assertion inside the signed Response. The Response's signature still validates (the signed element is unchanged), but the SP reads the injected Assertion.
- **Validation:** Forged NameID accepted while signature reports valid.
- **Pay-grade rationale:** Critical. Subtle and frequently overlooked by code review.

### Unsigned assertion bypass — neither Response nor Assertion checked
- **When to suspect:** SP integration documentation says "we trust the network channel" or "IdP is on the intranet."
- **Test:** Forge an entire SAML response with no signature whatsoever and submit it to `/saml/acs`.
- **Validation:** SP accepts.
- **Pay-grade rationale:** Critical. Anyone reachable by the SP can become any user.

### Missing recipient / audience restriction validation
- **When to suspect:** SP and IdP are deployed across multiple SPs sharing one IdP (common in enterprise setups). You have a legitimate assertion targeted at SP-A.
- **Test:** Submit the SP-A assertion (unmodified) to SP-B's `/saml/acs`. The signature is valid (legitimately signed by the shared IdP). The `Recipient` attribute in `<SubjectConfirmationData>` and the `Audience` element point at SP-A. If SP-B doesn't check, it will accept.
- **Validation:** You log into SP-B with an assertion that was issued for SP-A.
- **Pay-grade rationale:** High to critical depending on SP-B's privilege model.

### KeyInfo trust — attacker embeds their own certificate
- **When to suspect:** SP extracts the verification key from the `<ds:KeyInfo>` block of the response itself rather than from a configured trust anchor.
- **Test:** Generate your own keypair. Sign a forged response with your private key. Embed the matching public certificate in `<ds:X509Certificate>` inside the response's `<ds:KeyInfo>`. Submit.
- **Validation:** SP verifies the signature against the attacker-supplied certificate and accepts the assertion.
- **Pay-grade rationale:** Critical.

### IdP confusion — wrong Issuer accepted
- **When to suspect:** Multi-IdP SP that doesn't enforce which IdP issued which type of assertion. You control one IdP (a federated IdP, social login, or self-hosted Shibboleth).
- **Test:** Sign an assertion with your own IdP's key, set `<saml:Issuer>` to your IdP's entity ID, set NameID to a directory user from the *other* IdP's namespace. Submit to the SP.
- **Validation:** SP maps the NameID into the wrong directory and grants the other-IdP user's session.
- **Pay-grade rationale:** Critical.

### Replay attack — NotOnOrAfter unbounded or far in future
- **When to suspect:** SP doesn't track Assertion IDs to prevent replay, and the `Conditions/NotOnOrAfter` is set hours or days in the future.
- **Test:** Capture a legitimate SAML response (yours or victim's, if intercepted). Replay it later, possibly from a different IP. If accepted, replay works.
- **Validation:** Replay produces a fresh session.
- **Pay-grade rationale:** Medium to high. Higher when chained with a primitive that exposes assertions (logging, referer leak, intermediate proxy).

### XXE in SAML assertion
- **When to suspect:** SAML processor uses an older XML parser (libxml2 pre-2.9, default Java XMLInputFactory without entity restrictions, .NET XmlDocument without `XmlResolver = null`).
- **Test:** Inject an external entity:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <samlp:Response>
    <saml:Assertion>
      <saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>
    </saml:Assertion>
  </samlp:Response>
  ```
- **Validation:** SP error message reflects file contents, or out-of-band callback fires for `http://collaborator.attacker.com/x`.
- **Pay-grade rationale:** High when file read; critical when blind SSRF or RCE chains.

### Pre-account-takeover via SAML JIT provisioning
- **When to suspect:** SP supports both password login and SAML, with Just-In-Time provisioning.
- **Test:** Before the legitimate user signs up, log in via SAML asserting their NameID. SP auto-provisions an account bound to the SAML identity. When legitimate user later signs up via password, SP either merges (attacker access) or refuses to overwrite (victim lockout).
- **Validation:** Account merge or victim lockout demonstrated.
- **Pay-grade rationale:** High to critical depending on merge semantics.

### Encrypted assertion downgrade
- **When to suspect:** SP supports both signed-only and signed+encrypted assertions. Encryption is optional.
- **Test:** Capture an encrypted-assertion response. Re-encode without the encryption envelope (replace `<saml:EncryptedAssertion>` with a plain `<saml:Assertion>` you forged). Submit.
- **Validation:** SP accepts plaintext assertion despite earlier encrypted operation.
- **Pay-grade rationale:** High; opens XSW and parsing attacks on a previously-protected channel.

---

## Anti-Patterns (FP traps)

### "Signature present therefore signature verified"
- **Looks like:** You submit a tampered SAML response with the original signature still present. The SP doesn't error out, the response is accepted, and you assume the signature check is broken.
- **Actually is:** Some SPs parse the signature element but don't actually run the verification routine — they just check the element is present. To prove the bug, you need to show that a *signature whose computed value doesn't match the canonicalized body* is still accepted. This is a parser-vs-verifier disagreement, not a signature break.
- **How to disprove:** Take a legitimate response, change *one byte* in the assertion body without re-signing, submit. If accepted, the signature isn't actually verified. If rejected, the verifier is running — pursue XSW variants instead. Cite the specific bytes you changed in the report.

### XSW "succeeds" but you logged in as yourself
- **Looks like:** You apply XSW1 with NameID `admin@target.com`, submit, and reach a logged-in dashboard. Looks like ATO of admin.
- **Actually is:** Several SP libraries find the *signed* Assertion (your original) and extract NameID from there. The forged Assertion is parsed but ignored. You logged in as yourself — XSW didn't land.
- **How to disprove:** Check `/api/me`, the session cookie payload, audit logs, or any UI element that displays the current username. If it shows your own account, no XSW. Try the other XSW variants — different libraries pick different Assertions. Confirm with a uniquely-marked admin test account whose NameID local-part doesn't collide with your own.

### Comment injection that doesn't survive canonicalization
- **Looks like:** You injected `<!---->` in NameID and the response was accepted. You suspect the SP read the truncated form.
- **Actually is:** Some libraries call `c14n` (canonicalization) before passing the parsed value to application logic — the comment is normalized away identically by both the signer and the reader. The accept doesn't prove the comment exploit; the SP might just be reading the full NameID.
- **How to disprove:** Inspect the actual session — what NameID did the SP store? If it stored the full `admin@target.com@attacker.com`, comment injection didn't bypass the reader. If it stored `admin@target.com`, the reader stopped at the comment. The session/audit-log inspection is the only ground truth.

### SAML response returns HTTP 400 — assumed signature rejection
- **Looks like:** You posted a forged response, got HTTP 400, and assumed the SP rejected the signature.
- **Actually is:** 400 frequently comes from XML schema validation failing earlier in the pipeline (malformed timestamps, missing required attributes, unexpected element ordering). The signature check might never have run. To exercise the signature path, make the response schema-valid first.
- **How to disprove:** Run the forged response through `xmllint --schema saml-schema-protocol-2.0.xsd` (download from OASIS). Fix any schema errors. Re-submit. If 400 persists with schema-clean input, the SP is rejecting at a later layer — possibly the signature check, possibly the recipient/audience check. Read the error response body carefully or check `/var/log/` if you can reach it via another bug.

### Audience-mismatch "accepted" because the SP doesn't run validation on this flow
- **Looks like:** You replay an SP-A assertion at SP-B and get a session. Looks like missing audience validation.
- **Actually is:** Some SPs only enforce audience on the primary login flow but accept any signed assertion at backup flows (mobile-app login, API-key bootstrap). The audience check might exist on `/saml/acs` but not on `/api/saml/bootstrap`. The bug is real but the scope is narrower than "SP-B doesn't check audience" — it's "this specific endpoint doesn't."
- **How to disprove:** Try the same replay at the main `/saml/acs`. If rejected, the audience check exists on the primary path. Report the specific endpoint that skipped the check, and trace which session capabilities the bootstrap-flow session grants (often a subset). Severity should reflect actual reachable functionality, per the 7-Question Gate.
