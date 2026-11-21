import argparse
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cbh import cli


class ReportUtf8BomTests(unittest.TestCase):
    def test_report_preserves_metadata_with_or_without_bom(self):
        finding = (
            '---\nseverity: Low\nasset: example.test\n---\n'
            '# Sample report\n\n## Summary\nA formatting example.\n'
        )
        for prefix in ('', '\ufeff'):
            with self.subTest(bom=bool(prefix)), tempfile.TemporaryDirectory() as tmp:
                cwd = Path(tmp).resolve()
                source = cwd / 'finding.md'
                source.write_text(prefix + finding, encoding='utf-8')
                output = cwd / 'draft.md'
                args = argparse.Namespace(finding=str(source), platform='hackerone', out=str(output))
                with patch.object(Path, 'cwd', return_value=cwd), redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.cmd_report(args), 0)
                draft = output.read_text(encoding='utf-8')
                self.assertIn('**Severity:** Low', draft)
                self.assertIn('**Asset:** example.test', draft)
                self.assertNotIn('\ufeff', draft)
