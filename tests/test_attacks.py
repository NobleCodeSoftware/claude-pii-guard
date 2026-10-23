"""Regression tests for known bypass techniques. Each test reproduces the attack.

Synthetic data only: every value is built from tests/synthetic.py (generated addresses keep the reserved
.test domain, generated phone numbers stay in the Ofcom drama range used there).
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import pii_guard as g  # noqa: E402
import synthetic as s  # noqa: E402
from test_hook import HookCase  # noqa: E402

ALICE = s.EMAILS[0]
LOCAL, DOMAIN = ALICE.split("@")
PHONE_PREFIX = s.PHONES[0][:-3]  # Ofcom drama range, last three digits vary

DONT_BYPASS = "Do not add exceptions or allow markers yourself; ask the user."


def big_csv(rows=20000):
    lines = ["id,name,email,phone"]
    for i in range(rows):
        lines.append("%d,Customer %05d,%s%d@%s,%s%03d" % (i, i, LOCAL, i, DOMAIN, PHONE_PREFIX, i % 1000))
    return "\n".join(lines) + "\n"


class TestLargeInputs(HookCase):
    """Large inputs: many findings must not push the hook past its timeout (fail-open)."""

    def test_scan_text_is_not_quadratic(self):
        text = big_csv()
        cfg = json.loads(json.dumps(g.DEFAULT_CONFIG))
        start = time.monotonic()
        found = g.scan_text(text, cfg)  # no limit: every finding
        elapsed = time.monotonic() - start
        self.assertEqual(len(found), 40000)
        self.assertLess(elapsed, 2.0, "full scan of 40 000 findings took %.2f s" % elapsed)

    def test_single_long_line_with_many_hits(self):
        text = " ".join("%s%d@%s" % (LOCAL, i, DOMAIN) for i in range(20000))
        cfg = json.loads(json.dumps(g.DEFAULT_CONFIG))
        start = time.monotonic()
        self.assertEqual(len(g.scan_text(text, cfg)), 20000)
        self.assertLess(time.monotonic() - start, 2.0)

    def test_big_csv_write_is_denied_fast(self):
        content = big_csv()
        self.assertGreater(len(content), 900000)
        start = time.monotonic()
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "customers.csv"), "content": content})
        elapsed = time.monotonic() - start
        sys.stderr.write("\n[timing] Write customers.csv %d bytes, 40 000 values: %.3f s\n" % (len(content), elapsed))
        self.assertEqual(code, 0)
        self.assertDecision(out, "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("50 or more findings", reason)
        self.assertLess(elapsed, 2.0)


class TestMaxScanBytes(HookCase):
    """Oversized content: content beyond max_scan_bytes must not pass silently."""

    def filler_then_email(self, size):
        return "x" * size + "\n" + ALICE + "\n"

    def test_tail_beyond_default_limit_asks(self):
        content = self.filler_then_email(g.DEFAULT_CONFIG["max_scan_bytes"])
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "big.txt"), "content": content})
        self.assertDecision(out, "ask")
        self.assertIn("not scanned", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_tail_beyond_limit_in_warn_mode_warns(self):
        (self.repo / ".git").mkdir()
        (self.repo / "pii-guard.json").write_text(json.dumps({"mode": "warn", "max_scan_bytes": 1000}))
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "big.txt"),
                                               "content": self.filler_then_email(1000)})
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertIn("not scanned", out["systemMessage"])

    def test_chunks_cover_the_whole_limit(self):
        # 3 MB of lines (three chunks), the value is in the last one
        content = ("lorem ipsum 1.2.3\n" * 170000) + "PESEL 90210100005\n"
        self.assertGreater(len(content), 3000000)
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "big.txt"), "content": content})
        self.assertDecision(out, "deny")
        self.assertIn("line 170001", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_large_staged_diff_asks(self):
        self.git("init", "-q")
        (self.repo / "pii-guard.json").write_text(json.dumps({"max_scan_bytes": 2000}))
        (self.repo / "a.txt").write_text("y" * 5000 + "\n" + ALICE + "\n")
        self.git("add", "a.txt")
        code, out, _ = self.run_hook("Bash", {"command": 'git commit -m "data"'})
        self.assertIn(out["hookSpecificOutput"]["permissionDecision"], ("ask", "deny"))
        self.assertIn("not scanned", out["hookSpecificOutput"]["permissionDecisionReason"])


class TestNoSelfBypass(HookCase):
    """Self-bypass: the model must not be taught, or allowed, to switch the guard off silently."""

    def setUp(self):
        super().setUp()
        (self.repo / ".git").mkdir()

    def test_reason_does_not_teach_bypass(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.txt"), "content": "alice@mail.test"})
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn(DONT_BYPASS, reason)
        for hint in ("pii-guard.json", "pii-guard: allow", "allow_values", "ignore_paths"):
            self.assertNotIn(hint, reason)

    def test_write_adding_marker_asks(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.py"),
                                               "content": "mail = 'alice@mail.test'  # pii-guard: allow\n"})
        self.assertDecision(out, "ask")
        self.assertIn("allow marker", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_edit_adding_marker_asks_even_in_warn_mode(self):
        (self.repo / "pii-guard.json").write_text(json.dumps({"mode": "warn"}))
        f = self.repo / "a.py"
        f.write_text("mail = 'alice@mail.test'\n")
        code, out, _ = self.run_hook("Edit", {"file_path": str(f), "old_string": "mail = 'alice@mail.test'",
                                              "new_string": "mail = 'alice@mail.test'  # pii-guard: allow"})
        self.assertDecision(out, "ask")

    def test_existing_marker_is_not_a_new_one(self):
        f = self.repo / "a.py"
        f.write_text("mail = 'alice@mail.test'  # pii-guard: allow\nx = 1\n")
        code, out, _ = self.run_hook("Edit", {"file_path": str(f), "old_string": "x = 1", "new_string": "x = 2"})
        self.assertEqual((code, out), (0, None))

    def test_writing_repo_config_asks(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "pii-guard.json"),
                                               "content": '{"mode": "warn"}'})
        self.assertDecision(out, "ask")
        self.assertIn("configuration", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_writing_user_config_dir_asks(self):
        target = self.home / ".config" / "pii-guard" / "phrases.txt"
        code, out, _ = self.run_hook("Write", {"file_path": str(target), "content": "nothing\n"})
        self.assertDecision(out, "ask")

    def test_shell_edit_of_config_asks(self):
        for cmd in ("echo '{\"mode\": \"warn\"}' > pii-guard.json",
                    "sed -i 's/block/warn/' ~/.config/pii-guard/pii-guard.json",
                    "printf 'x  # pii-guard: allow' >> src/a.py"):
            code, out, _ = self.run_hook("Bash", {"command": cmd})
            self.assertDecision(out, "ask")

    def test_ordinary_commands_stay_silent(self):
        for cmd in ("ls -la", "python3 -m unittest", "cd claude-pii-guard && git status"):
            self.assertEqual(self.run_hook("Bash", {"command": cmd})[:2], (0, None), cmd)


class TestCommitDetectionBypasses(HookCase):
    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        (self.repo / "a.txt").write_text("PESEL 95323100001\n")
        self.git("add", "a.txt")

    def test_wrapped_and_qualified_git(self):
        git_path = shutil.which("git") or "/usr/bin/git"
        commands = [
            "bash -c 'git commit -m \"wip\"'",
            'sh -c "git commit -m wip"',
            "%s commit -m wip" % git_path,
            '"git" commit -m wip',
            "\\git commit -m wip",
            "env GIT_EDITOR=true git commit -m wip",
            "bash -c 'cd %s && git commit -m wip'" % self.repo,
        ]
        for cmd in commands:
            code, out, _ = self.run_hook("Bash", {"command": cmd})
            self.assertIsNotNone(out, cmd)
            self.assertDecision(out, "deny")

    def test_message_file_inside_bash_c(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        (self.repo / "msg.txt").write_text("Reported by alice@mail.test\n")
        code, out, _ = self.run_hook("Bash", {"command": "bash -c 'git commit -F msg.txt'"})
        self.assertDecision(out, "deny")


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
class TestMessageFileTypes(HookCase):
    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")

    def check_fast_ask(self, target):
        start = time.monotonic()
        code, out, _ = self.run_hook("Bash", {"command": "git commit -F %s" % target})
        self.assertLess(time.monotonic() - start, 3.0)
        self.assertDecision(out, "ask")
        self.assertIn("not a regular file", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_fifo_is_refused_without_blocking(self):
        os.mkfifo(str(self.repo / "msg.fifo"))
        self.check_fast_ask("msg.fifo")

    def test_directory_is_refused(self):
        (self.repo / "msgdir").mkdir()
        self.check_fast_ask("msgdir")

    @unittest.skipUnless(os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_device_is_refused(self):
        self.check_fast_ask("/dev/zero")


class TestMalformedInput(HookCase):
    def test_tool_input_not_an_object(self):
        for tin in (["a"], "text", 5, None):
            code, out, err = self.run_hook("Write", tin)
            self.assertEqual((code, out), (1, None), tin)
            self.assertIn("tool_input must be a JSON object", err)
            self.assertNotIn("Traceback", err)

    def test_tool_name_not_a_string(self):
        code, out, err = self.run_hook(["Write"], {})
        self.assertEqual((code, out), (1, None))
        self.assertNotIn("Traceback", err)


class TestGitOptionValues(HookCase):
    """Global git options with quoted or escaped values must not hide `commit` or `add`."""

    def setUp(self):
        super().setUp()
        self.outer = self.repo.parent
        self.repo = self.outer / "my repo"
        self.repo.mkdir()
        self.git("init", "-q")

    def run_from(self, cwd, command):
        payload = {"session_id": "test", "cwd": str(cwd), "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": command}}
        return self.run_hook("Bash", {}, stdin=json.dumps(payload))

    def test_commit_forms_with_quoted_or_escaped_option_values(self):
        (self.repo / "a.txt").write_text("contact %s\n" % ALICE)
        self.git("add", "a.txt")
        for cwd, command in ((self.outer, 'git -C "my repo" commit -m wip'),
                             (self.outer, "git -C my\\ repo commit -m wip"),
                             (self.repo, 'git -c user.name="A B" commit -m wip')):
            code, out, _ = self.run_from(cwd, command)
            self.assertIsNotNone(out, command)
            self.assertDecision(out, "deny")
            self.assertIn("a.txt, line 1: email address", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_add_all_forms_with_quoted_or_escaped_option_values(self):
        (self.repo / "untracked.txt").write_text("contact %s\n" % ALICE)
        for cwd, command in ((self.outer, 'git -C "my repo" add -A && git -C "my repo" commit -m wip'),
                             (self.outer, "git -C my\\ repo add -A && git -C my\\ repo commit -m wip"),
                             (self.repo, 'git -c user.name="A B" add -A && git -c user.name="A B" commit -m wip')):
            code, out, _ = self.run_from(cwd, command)
            self.assertIsNotNone(out, command)
            self.assertDecision(out, "deny")
            self.assertIn("untracked.txt (untracked, staged by git add)",
                          out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_command_that_cannot_be_tokenised_asks(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        code, out, _ = self.run_from(self.repo, 'git commit -m "unclosed quote')
        self.assertDecision(out, "ask")
        self.assertIn("could not be parsed", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_other_repository_or_index_asks(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        for command in ("GIT_INDEX_FILE=other.index git commit -m wip",
                        "env GIT_DIR=elsewhere/.git git commit -m wip",
                        "git --git-dir=.git --work-tree=. commit -m wip",
                        "git --work-tree . commit -m wip"):
            code, out, _ = self.run_from(self.repo, command)
            self.assertDecision(out, "ask")
            self.assertIn("another repository, work tree or index",
                          out["hookSpecificOutput"]["permissionDecisionReason"])


class TestLineContinuationsAndLooseForms(HookCase):
    """Line continuations, unknown options, aliases and unresolvable directories must not hide a commit."""

    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        (self.repo / "a.txt").write_text("contact %s\n" % ALICE)
        self.git("add", "a.txt")

    def reason(self, out):
        self.assertIsNotNone(out)
        return out["hookSpecificOutput"]["permissionDecisionReason"]

    def test_backslash_newline_between_git_and_commit(self):
        for command in ("git \\\ncommit -m x",
                        'git -c user.name="A B" \\\n  commit -m "x"',
                        "git \\\r\ncommit -m x"):
            code, out, _ = self.run_hook("Bash", {"command": command})
            self.assertDecision(out, "deny")
            self.assertIn("a.txt, line 1: email address", self.reason(out))

    def test_backslash_newline_before_add_all(self):
        (self.repo / "untracked.txt").write_text("contact %s\n" % ALICE)
        self.git("rm", "-q", "--cached", "a.txt")
        code, out, _ = self.run_hook("Bash", {"command": "git \\\nadd -A && git commit -m x"})
        self.assertDecision(out, "deny")
        self.assertIn("untracked.txt (untracked, staged by git add)", self.reason(out))

    def test_continuation_inside_single_quotes_is_kept(self):
        self.assertEqual(g.join_continuations("echo 'a\\\nb' \\\nok"), "echo 'a\\\nb' ok")

    def test_commit_the_token_parser_misses_is_scanned_and_asks(self):
        code, out, _ = self.run_hook("Bash", {"command": "git --frobnicate value commit -m x"})
        self.assertIn(out["hookSpecificOutput"]["permissionDecision"], ("deny", "ask"))
        reason = self.reason(out)
        self.assertIn("a.txt, line 1: email address", reason)
        self.assertIn("could not be parsed", reason)

    def test_other_git_commands_that_mention_commit_stay_silent(self):
        for command in ("git log --grep commit", "git help commit", "git show HEAD --stat # commit"):
            self.assertEqual(self.run_hook("Bash", {"command": command})[:2], (0, None), command)

    def test_alias_on_the_command_line_asks(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        code, out, _ = self.run_hook("Bash", {"command": "git -c alias.save=commit save -m x"})
        self.assertDecision(out, "ask")
        self.assertIn("defines a git alias", self.reason(out))

    def test_unresolvable_commit_directory_asks(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        for command in ("cd $PROJECT_DIR && git commit -m x", "git -C missing-dir commit -m x",
                        "pushd `pwd`/sub && git commit -m x", "cd - && git commit -m x"):
            code, out, _ = self.run_hook("Bash", {"command": command})
            self.assertDecision(out, "ask")
            self.assertIn("could not be resolved", self.reason(out))

    def test_pushd_is_followed_like_cd(self):
        outer = self.repo.parent
        payload = {"session_id": "test", "cwd": str(outer), "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": "pushd %s && git commit -m x" % self.repo.name}}
        code, out, _ = self.run_hook("Bash", {}, stdin=json.dumps(payload))
        self.assertDecision(out, "deny")
        self.assertIn("a.txt, line 1: email address", self.reason(out))


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
class TestReadTextRace(unittest.TestCase):
    def test_file_swapped_for_a_fifo_after_the_check_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = os.path.join(tmp, "swapped")
            os.mkfifo(fifo)
            start = time.monotonic()
            # Simulate the race: the first check still sees a regular file.
            with mock.patch.object(g, "_is_regular", return_value=True):
                self.assertEqual(g._read_text(fifo, 1000), (None, "not a regular file"))
            self.assertLess(time.monotonic() - start, 1.0)


if __name__ == "__main__":
    unittest.main()
