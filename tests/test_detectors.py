"""Detector, masking and configuration tests. Synthetic data only (see synthetic.py)."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import pii_guard as g  # noqa: E402
import synthetic as s  # noqa: E402


def config(**over):
    cfg = json.loads(json.dumps(g.DEFAULT_CONFIG))
    cfg.update(over)
    return cfg


def kinds(text, cfg=None, phrases=()):
    return [f.kind for f in g.scan_text(text, cfg or config(), phrases)]


class TestChecksums(unittest.TestCase):
    def test_pesel_valid(self):
        for p in s.PESELS:
            self.assertTrue(g.pesel_valid(p), p)

    def test_pesel_bad_checksum(self):
        for p in s.PESELS:
            bad = p[:10] + str((int(p[10]) + 1) % 10)
            self.assertFalse(g.pesel_valid(bad), bad)

    def test_pesel_bad_date(self):
        # checksum-valid but impossible dates: 30 February 2096, month 13, day 0
        def with_check(p10):
            w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
            return p10 + str((10 - sum(int(d) * x for d, x in zip(p10, w)) % 10) % 10)
        for p10 in ("9622300000", "9013010000", "9021000000", "9093010000"):
            self.assertFalse(g.pesel_valid(with_check(p10)), p10)

    def test_pesel_leap_year(self):
        # 29 February 2096 exists (leap), 29 February 2097 does not
        self.assertTrue(g.pesel_valid("96222900002"))
        w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
        p10 = "9722290000"
        self.assertFalse(g.pesel_valid(p10 + str((10 - sum(int(d) * x for d, x in zip(p10, w)) % 10) % 10)))

    def test_iban_valid_and_invalid(self):
        for i in s.IBANS:
            if i[0].isalpha():
                self.assertTrue(g.iban_valid(i), i)
        self.assertFalse(g.iban_valid("PL75000000000000000000000001"))  # wrong check digits
        self.assertFalse(g.iban_valid("PL7400000000000000000000001"))  # wrong length
        self.assertFalse(g.iban_valid("XX74000000000000000000000001"))  # unknown country

    def test_luhn(self):
        for c in s.CARDS:
            digits = c.replace(" ", "").replace("-", "")
            self.assertTrue(g.luhn_valid(digits), c)
            self.assertIsNotNone(g.card_brand(digits), c)
        self.assertFalse(g.luhn_valid("4111111111111112"))

    def test_card_prefix_required(self):
        # Luhn-valid, but no card network uses prefix 1 or 9
        self.assertTrue(g.luhn_valid("1234567812345670"))
        self.assertIsNone(g.card_brand("1234567812345670"))
        self.assertEqual(kinds("ref 1234567812345670"), [])


class TestDetection(unittest.TestCase):
    def test_emails(self):
        for e in s.EMAILS[:3]:
            self.assertEqual(kinds("contact: %s." % e), ["email address"], e)

    def test_allowed_domains_and_local_parts(self):
        for text in ("user@example.com", "info@sub.example.org", "x@host.localhost",
                     "git@github.com:org/repo.git", "noreply@vendor.invalid",
                     "12345+someone@users.noreply.github.com", "logo@2x.png", "@scope/package"):
            self.assertEqual(kinds(text), [], text)

    def test_phones(self):
        for p in s.PHONES[:9]:
            self.assertEqual(len(kinds("call %s now" % p)), 1, p)
        self.assertEqual(kinds("tel. 500000006"), ["phone number"])
        self.assertEqual(kinds("ref 500000006"), [])  # nine digits without context: not a phone

    def test_pesel_iban_card_in_text(self):
        self.assertEqual(kinds("PESEL: 90210100005"), ["PESEL"])
        self.assertEqual(kinds("PESEL: 90210100006"), [])
        for i in s.IBANS:
            self.assertEqual(len(kinds("account %s" % i)), 1, i)
            self.assertTrue(kinds("account %s" % i)[0].startswith("IBAN"), i)
        for c in s.CARDS:
            self.assertEqual(len(kinds("card %s" % c)), 1, c)
            self.assertTrue(kinds("card %s" % c)[0].startswith("payment card"), c)

    def test_phrases_case_insensitive(self):
        self.assertEqual(kinds("we discussed ACME secret project today", phrases=s.PHRASES),
                         ["private phrase"])
        self.assertEqual(kinds("nothing here", phrases=s.PHRASES), [])

    def test_line_numbers(self):
        text = "a\nb\nmail alice@mail.test\n\nPESEL 90210100005"
        self.assertEqual([f.line for f in g.scan_text(text, config())], [3, 5])

    def test_detectors_can_be_disabled(self):
        cfg = config()
        cfg["detectors"]["email"] = False
        self.assertEqual(kinds("alice@mail.test", cfg), [])


class TestFalsePositives(unittest.TestCase):
    SAMPLES = [
        "version 1.2.3", "v2.10.0", "1.0.0+20130313144700", "2.1.308 (Claude Code)",
        "commit 9fceb02d0ae598e95dc970b74767f19372d61af8", "short sha 9fceb02",
        "sha 1234567890123456789012345678901234567890",
        "uuid 123e4567-e89b-12d3-a456-426614174000", "uuid 00000000-0000-0000-0000-000000000000",
        "date 2026-10-22", "22.10.2026", "2026-10-22T11:25:00Z", "2026/10/22 11:25:00",
        "order ORD-2026-000123", "order #100234567", "Order 2026/10/000123", "invoice FV/2026/10/0042",
        "ts 1761130000", "ts 1761130000000", "ip 192.168.100.200", "color #a1b2c3",
        "price 1 234 567,89 PLN", "port 8080:8080", "range 1000-2000", "NIP 000-000-00-00",
        "seed 314159265358979323846", "id 12345678901234567890",
    ]

    def test_no_findings(self):
        for text in self.SAMPLES:
            self.assertEqual(kinds(text), [], text)


class TestMasking(unittest.TestCase):
    def test_mask_hides_values(self):
        for value in s.SYNTHETIC:
            masked = g.mask(value, "private phrase" if value in s.PHRASES else "")
            self.assertNotEqual(masked, value)
            self.assertNotIn(value, masked)
            self.assertEqual(len(masked) > 0, True)

    def test_mask_shape(self):
        self.assertEqual(g.mask("alice@mail.test"), "a***@m***.test")
        self.assertEqual(g.mask("90210100005", "PESEL"), "*********05")


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.repo = Path(self.tmp.name) / "repo"
        (self.home / ".config" / "pii-guard").mkdir(parents=True)
        (self.repo / ".git").mkdir(parents=True)
        self.env = dict(os.environ)
        os.environ["HOME"] = str(self.home)
        for k in ("XDG_CONFIG_HOME", "PII_GUARD_CONFIG", "PII_GUARD_PHRASES", "PII_GUARD_MODE"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)
        self.tmp.cleanup()

    def write_user(self, data):
        (self.home / ".config" / "pii-guard" / "pii-guard.json").write_text(json.dumps(data))

    def write_repo(self, data):
        (self.repo / "pii-guard.json").write_text(json.dumps(data))

    def test_defaults(self):
        cfg = g.load_config(str(self.repo), [])
        self.assertEqual(cfg["mode"], "block")

    def test_repo_overrides_user_and_lists_merge(self):
        self.write_user({"mode": "block", "allow_values": ["alice@mail.test"]})
        self.write_repo({"mode": "warn", "allow_domains": ["corp.test"], "ignore_paths": ["tests/fixtures/**"]})
        cfg = g.load_config(str(self.repo), [])
        self.assertEqual(cfg["mode"], "warn")
        self.assertIn("alice@mail.test", cfg["allow_values"])
        self.assertIn("corp.test", cfg["allow_domains"])
        self.assertIn("example.com", cfg["allow_domains"])

    def test_repo_config_lists_only_and_ignore(self):
        self.write_user({"repo_config": "lists"})
        self.write_repo({"mode": "warn", "allow_values": ["x"]})
        cfg = g.load_config(str(self.repo), [])
        self.assertEqual(cfg["mode"], "block")
        self.assertIn("x", cfg["allow_values"])
        self.write_user({"repo_config": "ignore"})
        cfg = g.load_config(str(self.repo), [])
        self.assertNotIn("x", cfg["allow_values"])

    def test_env_mode_wins(self):
        self.write_repo({"mode": "warn"})
        os.environ["PII_GUARD_MODE"] = "ask"
        self.assertEqual(g.load_config(str(self.repo), [])["mode"], "ask")

    def test_broken_config_is_reported_not_fatal(self):
        (self.repo / "pii-guard.json").write_text("{not json")
        notes = []
        cfg = g.load_config(str(self.repo), notes)
        self.assertEqual(cfg["mode"], "block")
        self.assertTrue(any("ignored" in n for n in notes))

    def test_phrases_file_from_user_config_only(self):
        outside = Path(self.tmp.name) / "phrases.txt"
        outside.write_text("# comment\nAcme Secret Project\nab\n")
        self.write_repo({"phrases_file": str(outside)})
        notes = []
        cfg = g.load_config(str(self.repo), notes)
        self.assertEqual(g.resolve_phrases(cfg, str(self.repo), notes), [])
        self.write_user({"phrases_file": str(outside)})
        cfg = g.load_config(str(self.repo), [])
        self.assertEqual(g.resolve_phrases(cfg, str(self.repo), []), ["Acme Secret Project"])

    def test_default_phrases_location_and_env(self):
        (self.home / ".config" / "pii-guard" / "phrases.txt").write_text("Acme Secret Project\n")
        cfg = g.load_config(str(self.repo), [])
        self.assertEqual(g.resolve_phrases(cfg, str(self.repo), []), ["Acme Secret Project"])

    def test_phrases_file_inside_repo_is_refused(self):
        inside = self.repo / "phrases.txt"
        inside.write_text("Acme Secret Project\n")
        os.environ["PII_GUARD_PHRASES"] = str(inside)
        notes = []
        cfg = g.load_config(str(self.repo), notes)
        self.assertEqual(g.resolve_phrases(cfg, str(self.repo), notes), [])
        self.assertTrue(any("inside the repository" in n for n in notes))

    def test_ignore_paths_globs(self):
        cfg = config(ignore_paths=["tests/fixtures/**", "*.snap", "docs/*.md"])
        self.assertTrue(g.path_ignored("tests/fixtures/a/b.json", cfg))
        self.assertTrue(g.path_ignored("./tests/fixtures/x.txt", cfg))
        self.assertTrue(g.path_ignored("src/ui/__snapshots__/x.snap", cfg))
        self.assertTrue(g.path_ignored("docs/a.md", cfg))
        self.assertFalse(g.path_ignored("docs/sub/a.md", cfg))
        self.assertFalse(g.path_ignored("src/tests/fixtures.py", cfg))
        self.assertFalse(g.path_ignored(".github/workflows/ci.yml", config(ignore_paths=["github/**"])))

    def test_allow_values_and_markers(self):
        cfg = config(allow_values=["+44 7700 900123"])
        self.assertEqual(kinds("call +447700900123", cfg), [])
        self.assertEqual(kinds("alice@mail.test  # pii-guard: allow"), [])
        self.assertEqual(kinds("alice@mail.test", config(allow_domains=["mail.test"])), [])


if __name__ == "__main__":
    unittest.main()
