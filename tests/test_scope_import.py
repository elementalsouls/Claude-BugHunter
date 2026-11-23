"""cbh scope import: program scope -> scope.md, checked against engine/scope.py.

Every fixture is synthetic (example.com / RFC 5737 addresses) but shaped like the
bounty-targets-data records and HackerOne MCP output the importer reads.
"""
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cbh import cli
from cbh import scope_import as si
from scope import _scope_from_md

REPO = Path(__file__).resolve().parent.parent


def _scope_of(text):
    fd, path = tempfile.mkstemp(suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        return _scope_from_md(path)
    finally:
        os.remove(path)


def _hunt_template(target="acme"):
    """The scope.md the bash `hunt` scaffolder writes today."""
    script = (REPO / "scripts" / "hunt.sh").read_text(encoding="utf-8")
    body = script.split("<<'SCOPEMD'\n", 1)[1].split("\nSCOPEMD", 1)[0]
    return f"# Scope — {target}\n{body}\n"


H1_RECORD = {
    "handle": "acme", "name": "Acme", "url": "https://hackerone.com/acme",
    "submission_state": "open", "offers_bounties": True,
    "targets": {
        "in_scope": [
            {"asset_identifier": "app.example.com", "asset_type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "critical", "instruction": "Main app"},
            {"asset_identifier": "*.api.example.com", "asset_type": "WILDCARD", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "high", "instruction": ""},
            {"asset_identifier": "https://portal.example.org:8443/", "asset_type": "URL",
             "eligible_for_bounty": False, "eligible_for_submission": True, "max_severity": "medium",
             "instruction": ""},
            {"asset_identifier": "https://docs.example.net/v2/reference", "asset_type": "API",
             "eligible_for_bounty": True, "eligible_for_submission": True, "max_severity": "high",
             "instruction": ""},
            {"asset_identifier": "https://v1.api.example.com/status", "asset_type": "API",
             "eligible_for_bounty": True, "eligible_for_submission": True, "max_severity": "high",
             "instruction": ""},
            {"asset_identifier": "203.0.113.0/28", "asset_type": "CIDR", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "low", "instruction": ""},
            {"asset_identifier": "com.example.mobile", "asset_type": "GOOGLE_PLAY_APP_ID",
             "eligible_for_bounty": True, "eligible_for_submission": True, "max_severity": "high",
             "instruction": ""},
            {"asset_identifier": "<your-tenant>.example.com", "asset_type": "URL",
             "eligible_for_bounty": True, "eligible_for_submission": True, "max_severity": "high",
             "instruction": ""},
        ],
        "out_of_scope": [
            {"asset_identifier": "legacy.api.example.com", "asset_type": "URL", "eligible_for_bounty": False,
             "eligible_for_submission": False, "max_severity": "none", "instruction": ""},
            {"asset_identifier": "https://app.example.com/blog", "asset_type": "URL",
             "eligible_for_bounty": False, "eligible_for_submission": False, "max_severity": "none",
             "instruction": ""},
        ],
    },
}


class ClassifyTests(unittest.TestCase):
    def rules(self, raw, typ="URL", side="in"):
        e = si.classify(raw, typ, side)
        return e.status, e.rules

    def test_exact_host_is_an_anchored_rule_not_a_domain_rule(self):
        self.assertEqual(self.rules("app.example.com"), ("rule", [r"re:^app\.example\.com$"]))
        self.assertEqual(self.rules("https://App.Example.com:8443/"), ("rule", [r"re:^app\.example\.com$"]))

    def test_wildcards_ips_and_networks(self):
        self.assertEqual(self.rules("*.example.com", "WILDCARD"), ("rule", ["*.example.com"]))
        self.assertEqual(self.rules("http://*.example.com/*", "WILDCARD"), ("rule", ["*.example.com"]))
        self.assertEqual(self.rules("203.0.113.7", "IP_ADDRESS"), ("rule", ["203.0.113.7"]))
        self.assertEqual(self.rules("203.0.113.7:8443", "IP_ADDRESS"), ("rule", ["203.0.113.7"]))
        self.assertEqual(self.rules("203.0.113.0/24", "CIDR"), ("rule", ["203.0.113.0/24"]))
        self.assertEqual(self.rules("2001:db8::/48", "CIDR"), ("rule", ["2001:db8::/48"]))
        self.assertEqual(self.rules("198.51.100.0 - 198.51.100.255", "iprange"), ("rule", ["198.51.100.0/24"]))
        self.assertEqual(self.rules("198.51.100.0-95", "iprange"),
                         ("rule", ["198.51.100.0/26", "198.51.100.64/27"]))

    def test_lists_braces_and_notes(self):
        self.assertEqual(self.rules("*.example.{com,net}", "WILDCARD"), ("rule", ["*.example.com", "*.example.net"]))
        self.assertEqual(self.rules("a.example.com,b.example.com")[1],
                         [r"re:^a\.example\.com$", r"re:^b\.example\.com$"])
        e = si.classify("*.old.example.com (legacy domain)", "website", "in")
        self.assertEqual((e.status, e.rules, e.reason), ("rule", ["*.old.example.com"], "legacy domain"))

    def test_idn_hosts_become_punycode(self):
        self.assertEqual(self.rules("bücher.example")[1], [r"re:^xn--bcher-kva\.example$"])

    def test_ambiguous_entries_go_to_review_never_to_rules(self):
        for raw, typ in (("<your-tenant>.example.com", "URL"), ("app[.staging].example.com", "website"),
                         ("All APIs used by the mobile app", "API"), ("www.*.example.*.com", "WILDCARD"),
                         ("*.example.com,uk,co.uk", "WILDCARD"), ("co.uk", "URL"), ("*.co.uk", "WILDCARD"),
                         ("*.example.{com,co.uk,}", "WILDCARD"), ("", "URL")):
            status, rules = self.rules(raw, typ)
            self.assertEqual(status, "review", raw)
            self.assertEqual(rules, [], raw)

    def test_path_limited_in_scope_asset_is_review_with_a_suggestion(self):
        e = si.classify("https://api.example.com/v1/users", "API", "in")
        self.assertEqual(e.status, "review")
        self.assertEqual(e.rules, [r"re:^api\.example\.com$"])
        self.assertIn("/v1/users", e.reason)

    def test_out_of_scope_side_fails_closed(self):
        # a mid-label wildcard still denies, as a regex
        e = si.classify("www.*.example.com", "WILDCARD", "out")
        self.assertEqual(e.status, "rule")
        self.assertTrue(_scope_of("## In scope\n\n- *.example.com\n\n## Out of scope\n\n"
                                  f"- `{e.rules[0]}`\n").reject_reason("https://www.eu.example.com"))
        # an untyped / "other" out-of-scope host is still denied
        self.assertEqual(self.rules("staging.example.com", "other", "out"),
                         ("rule", [r"re:^staging\.example\.com$"]))
        # a path-level exclusion cannot be a host rule: listed, not enforced
        status, rules = self.rules("https://app.example.com/blog", "URL", "out")
        self.assertEqual((status, rules), ("review", []))

    def test_non_host_assets_are_never_rules(self):
        for raw, typ, side in (("com.example.mobile", "GOOGLE_PLAY_APP_ID", "in"),
                               ("com.example.mobile", "GOOGLE_PLAY_APP_ID", "out"),
                               ("github.com/example/repo", "SOURCE_CODE", "in"),
                               ("app.example.com", "ios", "out")):
            self.assertEqual(self.rules(raw, typ, side), ("other", []), (raw, typ, side))


class RecordAndRenderTests(unittest.TestCase):
    def setUp(self):
        self.program = si.program_from_record("hackerone", H1_RECORD)
        self.program.source = "bounty-targets-data"
        self.md = si.render(self.program, today="2026-01-01")
        self.scope = _scope_of(self.md)

    def test_rules_round_trip_through_engine_scope(self):
        self.assertEqual(sorted(self.scope.in_scope),
                         sorted([r"re:^app\.example\.com$", "*.api.example.com",
                                 r"re:^portal\.example\.org$", "203.0.113.0/28"]))
        self.assertEqual(self.scope.out_of_scope, [r"re:^legacy\.api\.example\.com$"])

    def test_declared_assets_are_admitted_and_nothing_more(self):
        ok = self.scope.in_scope_host
        self.assertTrue(ok("https://app.example.com/login"))
        self.assertTrue(ok("https://v2.api.example.com/"))
        self.assertTrue(ok("https://portal.example.org/"))
        self.assertTrue(ok("https://203.0.113.9/"))
        self.assertFalse(ok("https://admin.app.example.com/"))     # exact host: no subdomains
        self.assertFalse(ok("https://example.com/"))               # apex never implied
        self.assertFalse(ok("https://legacy.api.example.com/"))    # deny wins over the wildcard
        self.assertFalse(ok("https://docs.example.net/"))          # path-limited: review only
        self.assertFalse(ok("https://tenant.example.com/"))        # placeholder: review only

    def test_review_other_and_covered_sections(self):
        review = self.md.split(si.REVIEW_HEADING, 1)[1].split("\n## ", 1)[0]
        self.assertIn("docs.example.net/v2/reference", review)
        self.assertIn(r"only /v2/reference is in scope. Scope checks are per host: move "
                      r"`re:^docs\.example\.net$` to In scope", review)
        self.assertIn("<your-tenant>.example.com", review)
        self.assertIn("do not test /blog", review)
        # covered by *.api.example.com, so it is not listed for review
        self.assertNotIn("v1.api.example.com/status", self.md)
        self.assertIn("com.example.mobile", self.md.split(si.OTHER_HEADING, 1)[1])
        self.assertEqual(self.program.summary()["covered"], 1)

    def test_path_limited_entries_group_per_host_and_redacted_entries_are_named(self):
        rec = {"handle": "acme", "url": "https://hackerone.com/acme", "targets": {"in_scope": [
            {"asset_identifier": f"https://shop.example.com/apps/{i}", "asset_type": "URL",
             "eligible_for_submission": True} for i in range(9)] + [
            {"asset_identifier": "\u2588\u2588\u2588\u2588\u2588", "asset_type": "URL",
             "eligible_for_submission": True},
            {"asset_identifier": "192.0.2.1, 192.0.2.2", "asset_type": "IP_ADDRESS",
             "eligible_for_submission": True}], "out_of_scope": [
            {"asset_identifier": f"https://www.example.com/{x}", "asset_type": "URL",
             "eligible_for_submission": False} for x in ("login", "signup")]}}
        p = si.program_from_record("hackerone", rec)
        review = si.section_bullets(p)["review"]
        self.assertEqual(len(review), 3)
        self.assertIn("only these paths are: /apps/0, /apps/1", review[0])
        self.assertIn("(+3 more)", review[0])
        self.assertIn("redacted in the public data", review[1])
        self.assertIn("do not test /login, /signup", review[2])
        self.assertEqual(p.summary()["review"], 3)
        self.assertEqual(_scope_of(si.render(p)).in_scope, ["192.0.2.1", "192.0.2.2"])

    def test_wildcard_path_entry_covered_by_a_wildcard(self):
        rec = {"handle": "acme", "targets": {"in_scope": [
            {"asset_identifier": "*.example.com", "asset_type": "WILDCARD", "eligible_for_submission": True},
            {"asset_identifier": "*.eu.example.com/console", "asset_type": "WILDCARD",
             "eligible_for_submission": True},
            {"asset_identifier": "198.51.100.0/24", "asset_type": "CIDR", "eligible_for_submission": True},
            {"asset_identifier": "198.51.100.7/admin", "asset_type": "URL", "eligible_for_submission": True}],
            "out_of_scope": []}}
        p = si.program_from_record("hackerone", rec)
        self.assertEqual(p.summary()["covered"], 2)
        self.assertNotIn(si.REVIEW_HEADING, si.render(p))

    def test_metadata_is_carried_on_each_rule(self):
        line = next(ln for ln in self.md.splitlines() if ln.startswith(r"- `re:^app\.example"))
        self.assertIn("bounty", line)
        self.assertIn("max critical", line)
        self.assertIn("Main app", line)
        self.assertIn("port 8443", self.md)

    def test_generated_headings_never_mention_scope(self):
        # engine/scope.py treats a level-2 heading that mentions scope specially, so the
        # generated non-rule sections must not.
        for heading in re.findall(r"^## .*$", self.md, re.M):
            if heading not in ("## In scope", "## Out of scope"):
                self.assertNotIn("scope", heading.lower(), heading)

    def test_out_of_scope_metadata_is_not_noise(self):
        out = self.md.split("## Out of scope", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("max none", out)
        self.assertNotIn("no bounty", out)


class OtherPlatformTests(unittest.TestCase):
    def test_bugcrowd_record(self):
        rec = {"name": "Acme", "url": "https://bugcrowd.com/engagements/acme-mbb",
               "targets": {"in_scope": [
                   {"type": "website", "target": "https://www.example.com/", "uri": "", "name": "Website",
                    "ipAddress": ""},
                   {"type": "api", "target": "api.example.com (REST)", "uri": "", "name": "", "ipAddress": ""},
                   {"type": "android", "target": "com.example.app", "uri": "", "name": "", "ipAddress": ""}],
                   "out_of_scope": [
                   {"type": "other", "target": "Any third-party service", "uri": "", "name": "", "ipAddress": ""},
                   {"type": "website", "target": "shop.example.com", "uri": "", "name": "", "ipAddress": ""}]}}
        p = si.program_from_record("bugcrowd", rec)
        self.assertEqual(p.handle, "acme-mbb")
        s = _scope_of(si.render(p))
        self.assertEqual(sorted(s.in_scope), sorted([r"re:^www\.example\.com$", r"re:^api\.example\.com$"]))
        self.assertEqual(s.out_of_scope, [r"re:^shop\.example\.com$"])

    def test_intigriti_tiers_and_ranges(self):
        rec = {"handle": "acmebbp", "company_handle": "acme", "name": "Acme BBP",
               "url": "https://www.intigriti.com/programs/acme/acmebbp/detail",
               "targets": {"in_scope": [
                   {"type": "wildcard", "endpoint": "*.example.com", "description": "", "impact": "Tier 1"},
                   {"type": "iprange", "endpoint": "198.51.100.0 - 198.51.100.127", "description": "",
                    "impact": "No Bounty"}],
                   "out_of_scope": [
                   {"type": "url", "endpoint": "status.example.com", "description": "", "impact": "Out of scope"}]}}
        p = si.program_from_record("intigriti", rec)
        self.assertEqual(p.handle, "acme/acmebbp")
        md = si.render(p)
        self.assertIn("Tier 1", md)
        self.assertIn("no bounty", md)
        self.assertIn("`198.51.100.0/25`", md)

    def test_yeswehack_record(self):
        rec = {"id": "acme", "name": "Acme", "targets": {
            "in_scope": [{"target": "https://app.example.com", "type": "web-application"},
                         {"target": "Any resource created in your account", "type": "other"}],
            "out_of_scope": [{"target": "blog.example.com", "type": "other"}]}}
        s = _scope_of(si.render(si.program_from_record("yeswehack", rec)))
        self.assertEqual(s.in_scope, [r"re:^app\.example\.com$"])
        self.assertEqual(s.out_of_scope, [r"re:^blog\.example\.com$"])

    def test_hackerone_mcp_output_and_policy_rules(self):
        mcp_out = {"program": "acme", "name": "Acme",
                   "in_scope": [{"asset_type": "URL", "asset_identifier": "app.example.com",
                                 "eligible_for_bounty": True, "eligible_for_submission": True,
                                 "max_severity": "critical", "instruction": None}],
                   "out_of_scope": [{"asset_type": "URL", "asset_identifier": "old.example.com",
                                     "eligible_for_bounty": False, "eligible_for_submission": False,
                                     "max_severity": None, "instruction": None}],
                   "policy": "Do not exceed 10 requests per second. Add the header X-Research: yes "
                             "to every request. Denial of service is out of bounds."}
        p = si.program_from_json(mcp_out)
        self.assertEqual(p.url, "https://hackerone.com/acme")
        s = _scope_of(si.render(p))
        self.assertEqual(s.in_scope, [r"re:^app\.example\.com$"])
        self.assertEqual(s.out_of_scope, [r"re:^old\.example\.com$"])
        tags = [c.split(":", 1)[0] for c in p.conduct]
        self.assertEqual(tags, ["rate limit", "required header", "no DoS"])

    def test_json_that_is_not_a_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            si.program_from_json({"hello": "world"})


class TextModeTests(unittest.TestCase):
    TEXT = """Acme program

Keep automated scanning under 5 requests per second.
Use your @wearehackerone.com alias for test accounts.

In Scope (3)
| Asset | Type | Max severity |
|---|---|---|
| *.example.com | Wildcard | Critical |
| https://api.example.net/v2 | API | High |
| 192.0.2.0/28 | CIDR | Low |

Out of scope
- admin.example.com
- Clickjacking on pages without sensitive actions

Rewards
- Critical: $5,000
- partner.example.org
"""

    def test_lists_tables_and_conduct(self):
        p = si.program_from_text(self.TEXT, name="acme")
        s = _scope_of(si.render(p))
        self.assertEqual(sorted(s.in_scope), sorted(["*.example.com", "192.0.2.0/28"]))
        self.assertEqual(s.out_of_scope, [r"re:^admin\.example\.com$"])
        self.assertEqual(p.exclusions, ["Clickjacking on pages without sensitive actions"])
        self.assertFalse(s.in_scope_host("https://partner.example.org/"))   # after "Rewards"
        self.assertEqual([c.split(":", 1)[0] for c in p.conduct], ["rate limit", "test account"])
        review = [e for e in p.entries if e.status == "review"]
        self.assertEqual([e.raw for e in review], ["https://api.example.net/v2"])

    def test_markdown_heading_ends_a_list(self):
        p = si.program_from_text("## In scope\n- a.example.com\n## Bounties\n- b.example.com\n")
        self.assertEqual(_scope_of(si.render(p)).in_scope, [r"re:^a\.example\.com$"])


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.program = si.program_from_record("hackerone", H1_RECORD)
        self.program.source = "bounty-targets-data"
        tmpl = _hunt_template()
        tmpl = tmpl.replace("- (paste in-scope asset list here)",
                            "- (paste in-scope asset list here)\n- manual.example.com — added by hand")
        tmpl += ("\n## Recon-seeded live hosts (from cbh manifest — UNVERIFIED)\n\n- seen.example.com\n")
        self.template = tmpl
        self.merged = si.merge(tmpl, self.program, today="2026-01-01")

    def test_merge_matches_standalone_rules_and_keeps_hand_edits(self):
        s = _scope_of(self.merged)
        standalone = _scope_of(si.render(self.program))
        self.assertEqual(sorted(s.in_scope), sorted(standalone.in_scope + ["manual.example.com"]))
        self.assertEqual(s.out_of_scope, standalone.out_of_scope)
        self.assertNotIn("(paste in-scope asset list here)", self.merged)
        self.assertIn("## Focus areas", self.merged)
        self.assertIn("## Recon-seeded live hosts", self.merged)
        self.assertFalse(s.in_scope_host("https://seen.example.com/"))

    def test_merge_is_idempotent_and_refreshes(self):
        self.assertEqual(si.merge(self.merged, self.program, today="2026-01-01"), self.merged)
        smaller = si.program_from_record("hackerone", {**H1_RECORD, "targets": {
            "in_scope": H1_RECORD["targets"]["in_scope"][:1], "out_of_scope": []}})
        again = si.merge(self.merged, smaller, today="2026-01-02")
        s = _scope_of(again)
        self.assertEqual(sorted(s.in_scope), sorted([r"re:^app\.example\.com$", "manual.example.com"]))
        self.assertEqual(s.out_of_scope, [])
        self.assertNotIn(si.REVIEW_HEADING, again)                  # nothing left to review
        self.assertEqual(again.count("> Imported from"), 1)

    def test_merge_never_drops_hand_written_content(self):
        mine = self.template.replace(
            "## Focus areas", "## Other assets\n\n- my own notes\n\n## Focus areas").replace(
            "- manual.example.com — added by hand", "- manual.example.com — added by hand\n"
            "- (no wildcard) legacy.example.com")
        merged = si.merge(mine, self.program, today="2026-01-01")
        self.assertIn("- my own notes", merged)
        self.assertIn("- (no wildcard) legacy.example.com", merged)

    def test_merge_into_a_file_without_scope_sections(self):
        merged = si.merge("# Notes\n\nfree text\n", self.program, today="2026-01-01")
        s = _scope_of(merged)
        self.assertIn(r"re:^app\.example\.com$", s.in_scope)
        self.assertIn("free text", merged)


class RefAndLookupTests(unittest.TestCase):
    def test_parse_ref(self):
        cases = {
            "h1:acme": ("hackerone", "acme"),
            "ywh:acme-bbp": ("yeswehack", "acme-bbp"),
            "https://hackerone.com/acme?type=team": ("hackerone", "acme"),
            "https://bugcrowd.com/engagements/acme-mbb": ("bugcrowd", "acme-mbb"),
            "https://app.intigriti.com/programs/acme/acmebbp/detail": ("intigriti", "acme/acmebbp"),
            "https://yeswehack.com/programs/acme": ("yeswehack", "acme"),
        }
        for ref, want in cases.items():
            self.assertEqual(si.parse_ref(ref), want, ref)
        for bad in ("acme", "gitlab:acme", "https://example.com/acme", "h1:"):
            with self.assertRaises(ValueError, msg=bad):
                si.parse_ref(bad)

    def test_find_program_with_suggestions(self):
        data = [H1_RECORD, {**H1_RECORD, "handle": "acme_vdp", "url": "https://hackerone.com/acme_vdp"}]
        self.assertIs(si.find_program("hackerone", data, "ACME"), H1_RECORD)
        with self.assertRaises(LookupError) as ctx:
            si.find_program("hackerone", data, "acme_vpd")
        self.assertIn("acme_vdp", str(ctx.exception))

    def test_intigriti_company_with_two_programs(self):
        a = {"handle": "acmebbp", "company_handle": "acme", "url": "u1", "targets": {}}
        b = {"handle": "acmevdp", "company_handle": "acme", "url": "u2", "targets": {}}
        self.assertIs(si.find_program("intigriti", [a, b], "acme/acmevdp"), b)
        self.assertIs(si.find_program("intigriti", [a, b], "acmebbp"), a)
        with self.assertRaises(LookupError):
            si.find_program("intigriti", [a, b], "acme")


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []

    def opener(self, body):
        def _open(req, timeout):
            self.calls.append(req.full_url)
            if isinstance(body, Exception):
                raise body
            return _Resp(body)
        return _open

    def test_download_then_cache(self):
        data, path = si.load_platform("hackerone", cache_dir=self.tmp.name,
                                      opener=self.opener(json.dumps([H1_RECORD]).encode()))
        self.assertEqual(data[0]["handle"], "acme")
        self.assertTrue(self.calls[0].endswith("/hackerone_data.json"))
        si.load_platform("hackerone", cache_dir=self.tmp.name, opener=self.opener(b"[]"))
        self.assertEqual(len(self.calls), 1)                         # fresh cache: no request

    def test_failed_refresh_falls_back_to_cache_and_never_caches_junk(self):
        si.load_platform("bugcrowd", cache_dir=self.tmp.name, opener=self.opener(b"[]"))
        logs = []
        data, _ = si.load_platform("bugcrowd", refresh=True, cache_dir=self.tmp.name,
                                   opener=self.opener(b"<html>rate limited</html>"), log=logs.append)
        self.assertEqual(data, [])
        self.assertIn("using cached", logs[0])
        with self.assertRaises(RuntimeError):
            si.load_platform("intigriti", cache_dir=self.tmp.name, opener=self.opener(OSError("offline")))


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["cbh", *argv]), redirect_stdout(out), redirect_stderr(err):
            code = cli.main()
        return code, out.getvalue(), err.getvalue()

    def test_import_from_local_dump_into_engagement(self):
        with tempfile.TemporaryDirectory() as d:
            dump = Path(d) / "hackerone_data.json"
            dump.write_text(json.dumps([H1_RECORD]), encoding="utf-8")
            target = Path(d) / "acme" / "scope.md"
            code, out, err = self.run_cli("scope", "import", "h1:acme", "--data", str(dump), "-o", str(target))
            self.assertEqual(code, 0, err)
            self.assertIn("4 in-scope rule(s), 1 out-of-scope rule(s)", err)
            self.assertIn("NOT rules", err)
            self.assertTrue(_scope_of(target.read_text(encoding="utf-8")).in_scope_host("https://app.example.com"))
            code, out, _ = self.run_cli("scope", "import", "h1:acme", "--data", str(dump))
            self.assertEqual(code, 0)
            self.assertTrue(out.startswith("# Scope — Acme"))

    def test_source_errors(self):
        self.assertEqual(self.run_cli("scope", "import")[0], 2)
        self.assertEqual(self.run_cli("scope", "import", "h1:a", "--text", "x")[0], 2)
        code, _, err = self.run_cli("scope", "import", "nope")
        self.assertEqual(code, 1)
        self.assertIn("program reference", err)

    def test_text_from_stdin(self):
        with mock.patch.object(sys, "stdin", io.StringIO("In scope\n- api.example.com\n")):
            code, out, _ = self.run_cli("scope", "import", "--text", "-", "--name", "acme")
        self.assertEqual(code, 0)
        self.assertIn(r"`re:^api\.example\.com$`", out)


if __name__ == "__main__":
    unittest.main()
