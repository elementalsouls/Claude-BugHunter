import json
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PluginManifestsTests(unittest.TestCase):
    def _load(self, relpath):
        path = os.path.join(REPO, relpath)
        self.assertTrue(os.path.isfile(path), f"missing manifest: {relpath}")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_versions_and_names_match(self):
        claude = self._load(".claude-plugin/plugin.json")
        gemini = self._load(".gemini-plugin/plugin.json")
        gemini_ext = self._load("gemini-extension.json")
        codex = self._load(".codex-plugin/plugin.json")

        for manifest in (gemini, gemini_ext, codex):
            self.assertEqual(manifest["name"], claude["name"])
            self.assertEqual(manifest["version"], claude["version"])

    def test_referenced_assets_and_mcp_exist(self):
        gemini = self._load(".gemini-plugin/plugin.json")
        codex = self._load(".codex-plugin/plugin.json")
        mcp_cfg = self._load("mcp_config.json")
        dot_mcp = self._load(".mcp.json")
        codex_mp = self._load(".agents/plugins/marketplace.json")

        self.assertTrue(os.path.isfile(os.path.join(REPO, gemini["logo"])))
        self.assertTrue(os.path.isfile(os.path.join(REPO, codex["interface"]["logo"])))
        self.assertTrue(os.path.isdir(os.path.join(REPO, codex["skills"])))
        self.assertTrue(os.path.isfile(os.path.join(REPO, codex["mcpServers"])))

        for cfg in (mcp_cfg, dot_mcp):
            h1 = cfg["mcpServers"]["hackerone"]
            self.assertEqual(h1["command"], "python3")
            self.assertTrue(os.path.isfile(os.path.join(REPO, h1["args"][0])))

        self.assertEqual(codex_mp["plugins"][0]["name"], codex["name"])

    def test_commands_are_available_as_skills(self):
        commands_dir = os.path.join(REPO, "commands")
        skills_dir = os.path.join(REPO, "skills")
        for fname in sorted(os.listdir(commands_dir)):
            if not fname.endswith(".md"):
                continue
            name = fname[:-3]
            self.assertTrue(
                os.path.isfile(os.path.join(skills_dir, name, "SKILL.md")),
                f"command '{name}' missing matching skills/{name}/SKILL.md for Gemini/Codex",
            )


if __name__ == "__main__":
    unittest.main()
