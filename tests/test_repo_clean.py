"""Guards for the published repository itself.

1. TestNoPersonalData scans every file with the plugin's own detectors (all of them on, no
   allow-lists) and fails on any value that is not in tests/synthetic.py. The plugin repo must never
   carry real data, including the maintainers' own.
2. TestNoPersonalData also fails on forbidden phrases, which can be supplied from CI without
   writing them into the repo: PII_GUARD_FORBIDDEN="phrase one,phrase two" (comma-separated,
   case-insensitive).
3. TestPluginLayout checks the plugin and marketplace manifests against the documented format.
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import pii_guard as g  # noqa: E402
import synthetic as s  # noqa: E402

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}


def repo_files():
    for path in sorted(ROOT.rglob("*")):
        if path.is_file() and not SKIP_DIRS.intersection(path.relative_to(ROOT).parts):
            yield path


class TestNoPersonalData(unittest.TestCase):
    def strict_config(self):
        cfg = json.loads(json.dumps(g.DEFAULT_CONFIG))
        cfg["allow_domains"] = []
        cfg["allow_local_parts"] = []
        cfg["allow_markers"] = []
        cfg["max_scan_bytes"] = 10 ** 8
        return cfg

    def test_only_synthetic_values(self):
        cfg = self.strict_config()
        allowed = {g.normalize(v) for v in s.SYNTHETIC}
        # Placeholder addresses used in documentation, all in reserved example.* domains.
        doc_domains = ("example.com", "example.org", "example.net")
        hits = []
        for path in repo_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for f in g.scan_text(text, cfg, s.PHRASES):
                if g.normalize(f.value) in allowed:
                    continue
                if f.kind == "email address" and f.value.lower().split("@")[1].endswith(doc_domains):
                    continue
                hits.append("%s:%d: %s %s" % (path.relative_to(ROOT), f.line, f.kind, g.mask(f.value, f.kind)))
        self.assertEqual(hits, [], "values outside tests/synthetic.py")

    def test_forbidden_phrases_from_environment(self):
        words = [w.strip().lower() for w in os.environ.get("PII_GUARD_FORBIDDEN", "").split(",") if w.strip()]
        hits = []
        for path in repo_files():
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            hits += ["%s: forbidden phrase #%d" % (path.relative_to(ROOT), i) for i, w in enumerate(words) if w in text]
        self.assertEqual(hits, [])

    def test_no_phrases_file_in_repo(self):
        names = [p.name for p in repo_files()]
        self.assertNotIn("phrases.txt", names)


class TestPluginLayout(unittest.TestCase):
    def load(self, rel):
        with open(ROOT / rel, encoding="utf-8") as fh:
            return json.load(fh)

    def test_manifest(self):
        plugin = self.load(".claude-plugin/plugin.json")
        self.assertEqual(plugin["name"], "pii-guard")
        self.assertRegex(plugin["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertFalse(plugin["name"].startswith(("claude-", "anthropic-")))  # reserved prefixes
        self.assertEqual(plugin["license"], "MIT")
        self.assertEqual(plugin["version"], g.VERSION)
        self.assertTrue(plugin["description"].startswith("Stops Claude Code from writing or committing personal data."))
        self.assertIn("Not affiliated with Anthropic", plugin["description"])
        self.assertTrue((ROOT / plugin["icon"]).is_file())

    def test_ci_actions_pinned_to_sha(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s*(\S+)", ci)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"@[0-9a-f]{40}$", u)

    def test_marketplace(self):
        market = self.load(".claude-plugin/marketplace.json")
        self.assertRegex(market["name"], r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
        self.assertIn("name", market["owner"])
        entries = {p["name"]: p for p in market["plugins"]}
        self.assertIn("pii-guard", entries)
        self.assertEqual(entries["pii-guard"]["source"], ".")

    def test_hooks_json(self):
        hooks = self.load("hooks/hooks.json")["hooks"]
        groups = hooks["PreToolUse"]
        matchers = set()
        for group in groups:
            matchers.update(group["matcher"].split("|"))
            for h in group["hooks"]:
                self.assertEqual(h["type"], "command")
                self.assertIn("${CLAUDE_PLUGIN_ROOT}/scripts/pii_guard.py", h["args"])
                self.assertEqual(h.get("onFailure"), "block")  # a crash or timeout must not let data through
        self.assertTrue({"Write", "Edit", "MultiEdit", "Bash"} <= matchers)
        for group in groups:
            for h in group["hooks"]:
                # The shared scan deadline must leave room for starting Python within the timeout.
                self.assertGreaterEqual(h["timeout"], g.TIME_BUDGET_SECONDS + 5)
        self.assertTrue((ROOT / "scripts" / "pii_guard.py").is_file())

    def test_changelog_mentions_version(self):
        self.assertIn("[%s]" % g.VERSION, (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))

    def test_no_network_modules(self):
        source = (ROOT / "scripts" / "pii_guard.py").read_text(encoding="utf-8")
        imports = set(re.findall(r"^(?:import|from)\s+([\w.]+)", source, re.M))
        self.assertTrue(imports <= {"bisect", "fnmatch", "json", "os", "re", "shlex", "stat", "subprocess", "sys", "time"}, imports)
        for banned in ("eval(", "exec(", "shell=True", "os.system", "urllib", "socket", "http.client"):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
