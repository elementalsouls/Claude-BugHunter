import unittest

from diff import diff_manifests, format_diff_report, has_signal, snapshot_filename


def _manifest(**overrides):
    base = {
        "schema_version": "1.0",
        "target": "acme.com",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "assets": [
            {"host": "api.acme.com", "tech": ["nginx"], "status": 200},
            {"host": "www.acme.com", "tech": ["cloudflare"], "status": 200},
        ],
        "ranked_surface": [
            {"url": "https://api.acme.com/v1/users", "host": "api.acme.com",
             "bug_classes": ["hunt-idor"], "priority": "P1"},
        ],
        "secrets": [],
    }
    base.update(overrides)
    return base


class DiffManifestsTests(unittest.TestCase):
    def test_first_run_is_flagged_and_report_says_so(self):
        diff = diff_manifests(None, _manifest())
        self.assertTrue(diff["first_run"])
        # Everything is "new" relative to an empty baseline — the CLI/report layer
        # is responsible for suppressing the signal callout on a first run, not
        # diff_manifests itself (it has no opinion on "first run", just on deltas).
        report = format_diff_report(diff)
        self.assertIn("First run", report)

    def test_identical_manifests_produce_no_signal(self):
        m = _manifest()
        diff = diff_manifests(m, m)
        self.assertFalse(diff["first_run"])
        self.assertFalse(has_signal(diff))
        self.assertEqual(diff["new_hosts"], [])

    def test_new_host_detected(self):
        old = _manifest()
        new = _manifest(assets=old["assets"] + [{"host": "staging.acme.com", "tech": [], "status": 200}])
        diff = diff_manifests(old, new)
        self.assertIn("staging.acme.com", diff["new_hosts"])
        self.assertTrue(has_signal(diff))

    def test_removed_host_detected_but_not_a_signal(self):
        old = _manifest()
        new = _manifest(assets=[old["assets"][0]])  # drop www.acme.com
        diff = diff_manifests(old, new)
        self.assertIn("www.acme.com", diff["removed_hosts"])
        # Removed hosts alone (decommission) aren't "new attack surface" signal.
        self.assertFalse(has_signal(diff))

    def test_tech_change_detected(self):
        old = _manifest()
        new_assets = [dict(old["assets"][0], tech=["nginx", "php"]), old["assets"][1]]
        diff = diff_manifests(old, _manifest(assets=new_assets))
        self.assertEqual(len(diff["tech_changes"]), 1)
        self.assertEqual(diff["tech_changes"][0]["host"], "api.acme.com")
        self.assertTrue(has_signal(diff))

    def test_status_flip_detected(self):
        old = _manifest()
        new_assets = [dict(old["assets"][0], status=403), old["assets"][1]]
        diff = diff_manifests(old, _manifest(assets=new_assets))
        self.assertEqual(diff["status_changes"][0]["old_status"], 200)
        self.assertEqual(diff["status_changes"][0]["new_status"], 403)

    def test_new_ranked_surface_entry(self):
        old = _manifest()
        new_surface = old["ranked_surface"] + [
            {"url": "https://api.acme.com/v2/users", "host": "api.acme.com",
             "bug_classes": ["hunt-idor"], "priority": "P1"},
        ]
        diff = diff_manifests(old, _manifest(ranked_surface=new_surface))
        self.assertEqual(len(diff["new_ranked_surface"]), 1)
        self.assertEqual(diff["new_ranked_surface"][0]["url"], "https://api.acme.com/v2/users")

    def test_new_secret_detected_by_identity_not_just_count(self):
        old = _manifest(secrets=[{"pattern": "aws_key", "source": "a.js", "category": "cloud", "severity": "high"}])
        new = _manifest(secrets=old["secrets"] + [
            {"pattern": "stripe_key", "source": "b.js", "category": "payment", "severity": "critical"},
        ])
        diff = diff_manifests(old, new)
        self.assertEqual(len(diff["new_secrets"]), 1)
        self.assertEqual(diff["new_secrets"][0]["pattern"], "stripe_key")

    def test_malformed_manifest_does_not_raise(self):
        diff = diff_manifests({"assets": "not-a-list"}, {"assets": None, "target": "x"})
        self.assertEqual(diff["new_hosts"], [])
        self.assertEqual(diff["target"], "x")

    def test_report_mentions_new_hosts(self):
        old = _manifest()
        new = _manifest(assets=old["assets"] + [{"host": "beta.acme.com", "tech": [], "status": 200}])
        diff = diff_manifests(old, new)
        report = format_diff_report(diff)
        self.assertIn("beta.acme.com", report)
        self.assertIn("New assets", report)

    def test_snapshot_filename_is_sortable(self):
        import datetime
        a = snapshot_filename(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        b = snapshot_filename(datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc))
        self.assertLess(a, b)


if __name__ == "__main__":
    unittest.main()
