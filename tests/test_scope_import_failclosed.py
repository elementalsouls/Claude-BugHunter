"""cbh scope import — the out-of-scope side must fail CLOSED (#235).

Three fail-open paths: a `| Type | Asset |` table let `_first_cell` take the type
column ("Web") as the identifier, so the excluded host was dropped; a host carrying
a description ("billing.example.com - legacy billing") fell through to free-text
exclusions instead of a deny rule / manual review; and markdown emphasis
(`**vpn.example.com**`) leaked the `**` into the host. All three must deny or
flag — never silently drop an excluded host.
"""
import os
import tempfile
import unittest

from cbh import scope_import as si
from scope import _scope_from_md


def _scope_of(text):
    fd, path = tempfile.mkstemp(suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        return _scope_from_md(path)
    finally:
        os.remove(path)


class OutOfScopeFailClosed(unittest.TestCase):
    def test_table_and_host_with_description_fail_closed(self):
        p = si.program_from_text(
            "In scope\n- *.example.com\n"
            "Out of scope\n"
            "| Type | Asset |\n|------|-------|\n| Web | admin.example.com |\n"
            "- billing.example.com - legacy billing\n"
            "- **vpn.example.com**\n")
        s = _scope_of(si.render(p))
        self.assertEqual(sorted(s.out_of_scope),
                         sorted([r"re:^admin\.example\.com$", r"re:^vpn\.example\.com$"]))
        for host in ("admin.example.com", "vpn.example.com"):
            self.assertFalse(s.in_scope_host(host), f"{host} stayed in scope")
        review = [e.raw for e in p.entries if e.status == "review"]
        self.assertIn("billing.example.com - legacy billing", review)
        self.assertNotIn("Type", p.exclusions)
        self.assertNotIn("Web", p.exclusions)

    def test_type_asset_column_order_both_work(self):
        for tbl in ("| Type | Asset |\n|--|--|\n| Web | a.example.com |\n",
                    "| Asset | Type |\n|--|--|\n| a.example.com | Web |\n"):
            p = si.program_from_text("Out of scope\n" + tbl)
            s = _scope_of(si.render(p))
            self.assertIn(r"re:^a\.example\.com$", s.out_of_scope)


if __name__ == "__main__":
    unittest.main()
