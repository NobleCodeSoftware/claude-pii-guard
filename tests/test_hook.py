"""Integration tests: the hook as Claude Code runs it, JSON on stdin, decision on stdout.

Each test runs the script in a fresh process with HOME pointing at a temporary directory, so no real
user configuration or phrases file is read. Synthetic data only (see synthetic.py).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pii_guard.py"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import pii_guard as g  # noqa: E402
import synthetic as s  # noqa: E402


class HookCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("PII_GUARD_", "GIT_")) and k != "XDG_CONFIG_HOME"}
        self.env["HOME"] = str(self.home)
        self.env["GIT_CONFIG_GLOBAL"] = os.devnull
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git"] + list(args), cwd=self.repo, env=self.env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def init_repo(self):
        self.git("init", "-q")

    def run_hook(self, tool, tool_input, stdin=None, env=None):
        payload = {
            "session_id": "test", "transcript_path": "/dev/null", "cwd": str(self.repo),
            "permission_mode": "default", "hook_event_name": "PreToolUse",
            "tool_name": tool, "tool_input": tool_input, "tool_use_id": "toolu_test",
        }
        e = dict(self.env)
        e.update(env or {})
        res = subprocess.run([sys.executable, str(SCRIPT)], input=stdin if stdin is not None else json.dumps(payload),
                             capture_output=True, text=True, env=e, cwd=str(self.repo), timeout=30)
        out = json.loads(res.stdout) if res.stdout.strip() else None
        return res.returncode, out, res.stderr

    def assertDecision(self, out, decision):
        self.assertIsNotNone(out)
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(out["hookSpecificOutput"].get("permissionDecision"), decision)


class TestFileTools(HookCase):
    def test_clean_write_is_silent(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.py"), "content": "x = 1\n"})
        self.assertEqual((code, out), (0, None))

    def test_write_with_email_is_denied(self):
        content = "name = 'Alice'\nmail = 'alice@mail.test'\n"
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "src" / "a.py"), "content": content})
        self.assertEqual(code, 0)
        self.assertDecision(out, "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("line 2", reason)
        self.assertIn("email address", reason)
        self.assertIn("a***@m***.test", reason)
        self.assertNotIn("alice@mail.test", reason)
        # The model is told not to bypass the guard, and is not taught how to.
        self.assertIn("Do not add exceptions or allow markers yourself; ask the user.", reason)
        self.assertNotIn("pii-guard.json", reason)
        self.assertNotIn("pii-guard: allow", reason)
        self.assertIn("systemMessage", out)

    def test_every_synthetic_kind_is_denied(self):
        for value in s.PESELS[:1] + s.IBANS[:1] + s.CARDS[:1] + s.PHONES[:1]:
            code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.txt"), "content": "v: %s\n" % value})
            self.assertEqual(code, 0)
            self.assertDecision(out, "deny")
            self.assertNotIn(value, json.dumps(out))

    def test_warn_mode_allows_with_message(self):
        (self.repo / ".git").mkdir()
        (self.repo / "pii-guard.json").write_text(json.dumps({"mode": "warn"}))
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.txt"), "content": "PESEL 90210100005"})
        self.assertEqual(code, 0)
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertIn("PESEL", out["systemMessage"])
        self.assertIn("mode: warn", out["hookSpecificOutput"]["additionalContext"])

    def test_ask_mode_from_environment(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.txt"), "content": "PESEL 90210100005"},
                                     env={"PII_GUARD_MODE": "ask"})
        self.assertDecision(out, "ask")

    def test_disable_switch(self):
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.txt"), "content": "PESEL 90210100005"},
                                     env={"PII_GUARD_DISABLE": "1"})
        self.assertEqual((code, out), (0, None))

    def test_ignore_paths(self):
        (self.repo / ".git").mkdir()
        (self.repo / "pii-guard.json").write_text(json.dumps({"ignore_paths": ["tests/fixtures/**"]}))
        target = self.repo / "tests" / "fixtures" / "users.json"
        code, out, _ = self.run_hook("Write", {"file_path": str(target), "content": '{"mail": "alice@mail.test"}'})
        self.assertEqual((code, out), (0, None))
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "src" / "users.json"),
                                               "content": '{"mail": "alice@mail.test"}'})
        self.assertDecision(out, "deny")

    def test_edit_reports_line_in_file(self):
        f = self.repo / "notes.md"
        f.write_text("one\ntwo\nthree\nTODO\nfive\n")
        code, out, _ = self.run_hook("Edit", {"file_path": str(f), "old_string": "TODO",
                                              "new_string": "Card 4111 1111 1111 1111", "replace_all": False})
        self.assertDecision(out, "deny")
        self.assertIn("line 4", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIn("Visa", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_edit_keeping_existing_value_is_allowed(self):
        f = self.repo / "notes.md"
        f.write_text("contact alice@mail.test\n")
        code, out, _ = self.run_hook("Edit", {"file_path": str(f), "old_string": "contact alice@mail.test",
                                              "new_string": "Contact: alice@mail.test"})
        self.assertEqual((code, out), (0, None))

    def test_multiedit(self):
        f = self.repo / "a.txt"
        f.write_text("a\nb\n")
        edits = [{"old_string": "a", "new_string": "a2"}, {"old_string": "b", "new_string": "IBAN GB82 WEST 1234 5698 7654 32"}]
        code, out, _ = self.run_hook("MultiEdit", {"file_path": str(f), "edits": edits})
        self.assertDecision(out, "deny")
        self.assertIn("line 2", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_private_phrases_from_user_file(self):
        cfg_dir = self.home / ".config" / "pii-guard"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "phrases.txt").write_text("Acme Secret Project\n")
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "a.md"), "content": "About acme secret project."})
        self.assertDecision(out, "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("private phrase", reason)
        self.assertNotIn("acme secret project", reason.lower())

    def test_other_tools_and_commands_pass(self):
        self.assertEqual(self.run_hook("Read", {"file_path": "/etc/hostname"})[:2], (0, None))
        self.assertEqual(self.run_hook("Bash", {"command": "echo alice@mail.test"})[:2], (0, None))
        self.assertEqual(self.run_hook("Bash", {"command": "git commit-tree abc"})[:2], (0, None))

    def test_invalid_input_exits_1_so_the_call_is_blocked(self):
        # hooks/hooks.json declares onFailure: "block", so Claude Code blocks the call on exit 1.
        code, out, err = self.run_hook("Write", {}, stdin="not json")
        self.assertEqual((code, out), (1, None))
        self.assertIn("invalid hook input", err)

    def test_fast(self):
        content = ("lorem ipsum dolor sit amet 1.2.3 2026-10-22 " * 20 + "\n") * 2000  # about 1.8 MB
        start = time.monotonic()
        code, out, _ = self.run_hook("Write", {"file_path": str(self.repo / "big.txt"), "content": content})
        self.assertEqual((code, out), (0, None))
        self.assertLess(time.monotonic() - start, 3.0)


class TestGitCommit(HookCase):
    def setUp(self):
        super().setUp()
        self.init_repo()

    def commit(self, command, env=None):
        return self.run_hook("Bash", {"command": command, "description": "commit"}, env=env)

    def test_clean_commit_passes(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        self.assertEqual(self.commit('git commit -m "Add greeting"')[:2], (0, None))

    def test_staged_pesel_is_denied_with_line(self):
        (self.repo / "data.csv").write_text("id,name\n1,Alice\n2,Bob 90210100005\n")
        self.git("add", "data.csv")
        code, out, _ = self.commit('git commit -m "Add data"')
        self.assertEqual(code, 0)
        self.assertDecision(out, "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("data.csv, line 3: PESEL", reason)

    def test_unstaged_changes_are_not_scanned(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        (self.repo / "b.txt").write_text("alice@mail.test\n")
        self.assertEqual(self.commit('git commit -m "Add greeting"')[:2], (0, None))

    def test_git_add_all_then_commit_scans_untracked(self):
        (self.repo / "b.txt").write_text("x\ncard 5555555555554444\n")
        code, out, _ = self.commit('git add -A && git commit -m "wip"')
        self.assertDecision(out, "deny")
        self.assertIn("b.txt", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_commit_message_is_scanned(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        cmd = "git commit -m \"$(cat <<'EOF'\nFix bug reported by carol+news@corp.test\nEOF\n)\""
        code, out, _ = self.commit(cmd)
        self.assertDecision(out, "deny")
        self.assertIn("commit", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_trailers_are_allowed(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        cmd = 'git commit -m "Add greeting" -m "Signed-off-by: Bob <bob.builder@shop.invalid>"'
        self.assertEqual(self.commit(cmd)[:2], (0, None))

    def test_message_file(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        (self.repo / ".msg").write_text("Call +44 7700 900123\n")
        code, out, _ = self.commit("git commit -F .msg")
        self.assertDecision(out, "deny")

    def test_git_dash_c_directory(self):
        # The hook runs with cwd outside any repository; only following -C finds the staged IBAN.
        outside = Path(self.tmp.name) / "elsewhere"
        outside.mkdir()
        (self.repo / "a.txt").write_text("IBAN DE09000000000000000001\n")
        self.git("add", "a.txt")
        payload = {"session_id": "test", "cwd": str(outside), "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": "git -C %s commit -m wip" % self.repo}}
        code, out, _ = self.run_hook("Bash", {}, stdin=json.dumps(payload))
        self.assertDecision(out, "deny")
        self.assertIn("a.txt, line 1: IBAN", out["hookSpecificOutput"]["permissionDecisionReason"])
        # Without -C the same command finds no repository and only the message is scanned.
        payload["tool_input"] = {"command": "git commit -m wip"}
        code, out, _ = self.run_hook("Bash", {}, stdin=json.dumps(payload))
        self.assertNotIn("hookSpecificOutput", out or {})

    def test_powershell_commit(self):
        (self.repo / "a.txt").write_text("PESEL 95323100001\n")
        self.git("add", "a.txt")
        code, out, _ = self.run_hook("PowerShell", {"command": "git commit -m wip"})
        self.assertDecision(out, "deny")

    def test_external_diff_is_not_executed(self):
        marker = Path(self.tmp.name) / "executed"
        script = Path(self.tmp.name) / "evil.sh"
        script.write_text("#!/bin/sh\ntouch %s\n" % marker)
        script.chmod(0o755)
        self.git("config", "diff.external", str(script))
        (self.repo / ".gitattributes").write_text("*.txt diff=evil\n")
        self.git("config", "diff.evil.textconv", str(script))
        self.git("config", "diff.evil.command", str(script))
        (self.repo / "a.txt").write_text("PESEL 95323100001\n")
        self.git("add", "a.txt", ".gitattributes")
        code, out, _ = self.commit('git commit -m "x"')
        self.assertDecision(out, "deny")
        self.assertFalse(marker.exists(), "a configured diff program was executed")


class TestContentThatIsNotScanned(HookCase):
    """Binary files are skipped with a visible note; unreadable files ask instead of passing."""

    def setUp(self):
        super().setUp()
        self.init_repo()
        (self.repo / "a.txt").write_text("hello\n")

    def test_untracked_binary_under_add_all_is_noted(self):
        (self.repo / "logo.bin").write_bytes(b"\x89PNG\0\0\0" + b"alice@mail.test")
        code, out, _ = self.run_hook("Bash", {"command": 'git add -A && git commit -m "Add logo"'})
        self.assertEqual(code, 0)
        self.assertNotIn("hookSpecificOutput", out)
        self.assertIn("binary files skipped", out["systemMessage"])
        self.assertIn("logo.bin", out["systemMessage"])

    def test_staged_binary_is_noted(self):
        (self.repo / "logo.bin").write_bytes(b"\x89PNG\0\0\0data")
        self.git("add", "a.txt", "logo.bin")
        code, out, _ = self.run_hook("Bash", {"command": 'git commit -m "Add logo"'})
        self.assertNotIn("hookSpecificOutput", out)
        self.assertIn("logo.bin", out["systemMessage"])

    def test_text_file_marked_binary_by_gitattributes_is_scanned(self):
        (self.repo / ".gitattributes").write_text("*.csv -diff\n")
        (self.repo / "people.csv").write_text("id;mail\n1;alice@mail.test\n")
        self.git("add", ".gitattributes", "people.csv")
        code, out, _ = self.run_hook("Bash", {"command": 'git commit -m "Add people"'})
        self.assertDecision(out, "deny")
        self.assertIn("people.csv (staged, no text diff), line 2: email address",
                      out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_staged_text_is_read_from_the_index_not_the_working_tree(self):
        # The staged blob is text with an e-mail address; a NUL byte written into the working copy
        # afterwards must not turn it into a skipped binary file.
        (self.repo / ".gitattributes").write_text("*.csv -diff\n")
        people = self.repo / "people.csv"
        people.write_text("id;mail\n1;alice@mail.test\n")
        self.git("add", ".gitattributes", "people.csv")
        people.write_bytes(b"\0binary now\n")
        code, out, _ = self.run_hook("Bash", {"command": 'git commit -m "Add people"'})
        self.assertDecision(out, "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("people.csv (staged, no text diff), line 2: email address", reason)
        self.assertNotIn("binary files skipped", json.dumps(out))

    def test_staged_blob_that_cannot_be_read_asks(self):
        (self.repo / ".gitattributes").write_text("*.csv -diff\n")
        (self.repo / "people.csv").write_text("id;mail\n1;user@example.com\n")
        self.git("add", ".gitattributes", "people.csv")
        payload = {"tool_name": "Bash", "tool_input": {"command": 'git commit -m "Add people"'},
                   "cwd": str(self.repo)}
        real_git = g._git

        def failing_cat_file(args, *rest):
            return g.GitResult() if args[0] == "cat-file" else real_git(args, *rest)

        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(g, "_git", failing_cat_file):
            out = g.evaluate(payload)
        self.assertDecision(out, "ask")
        self.assertIn("people.csv (staged, no text diff): git could not read the staged file",
                      out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_untracked_file_that_cannot_be_read_asks(self):
        os.symlink(str(self.repo / "missing-target.txt"), str(self.repo / "dangling.txt"))
        code, out, _ = self.run_hook("Bash", {"command": 'git add -A && git commit -m "wip"'})
        self.assertDecision(out, "ask")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("dangling.txt", reason)
        self.assertIn("not a regular file", reason)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read any file")
    def test_untracked_file_without_read_permission_asks(self):
        locked = self.repo / "locked.txt"
        locked.write_text("alice@mail.test\n")
        locked.chmod(0)
        try:
            code, out, _ = self.run_hook("Bash", {"command": 'git add -A && git commit -m "wip"'})
        finally:
            locked.chmod(0o644)
        self.assertDecision(out, "ask")
        self.assertIn("unreadable", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_untracked_file_that_cannot_be_read_warns_in_warn_mode(self):
        os.symlink(str(self.repo / "missing-target.txt"), str(self.repo / "dangling.txt"))
        code, out, _ = self.run_hook("Bash", {"command": 'git add -A && git commit -m "wip"'},
                                     env={"PII_GUARD_MODE": "warn"})
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertIn("could not be scanned", out["systemMessage"])


class TestScanCommand(HookCase):
    def scan(self, *paths):
        res = subprocess.run([sys.executable, str(SCRIPT), "scan"] + [str(p) for p in paths],
                             capture_output=True, text=True, env=self.env, cwd=str(self.repo), timeout=30)
        return res.returncode, res.stdout

    def test_clean_text_file_exits_0(self):
        (self.repo / "a.txt").write_text("hello\n")
        self.assertEqual(self.scan(self.repo / "a.txt"), (0, ""))

    def test_finding_exits_1(self):
        (self.repo / "a.txt").write_text("mail alice@mail.test\n")
        code, stdout = self.scan(self.repo / "a.txt")
        self.assertEqual(code, 1)
        self.assertIn("email address", stdout)

    def test_binary_file_is_reported_as_skipped(self):
        (self.repo / "logo.bin").write_bytes(b"\x89PNG\0\0\0data")
        code, stdout = self.scan(self.repo / "logo.bin")
        self.assertEqual(code, 0)
        self.assertIn("logo.bin: binary file skipped, not scanned", stdout)

    def test_file_that_cannot_be_read_exits_1(self):
        os.symlink(str(self.repo / "missing-target.txt"), str(self.repo / "dangling.txt"))
        code, stdout = self.scan(self.repo / "dangling.txt")
        self.assertEqual(code, 1)
        self.assertIn("dangling.txt: not scanned (not a regular file)", stdout)


class TestTimeBudget(HookCase):
    """A slow git must not push the hook past its timeout; what is left is treated as not scanned."""

    def setUp(self):
        super().setUp()
        self.init_repo()
        (self.repo / "a.txt").write_text("hello\n")
        self.git("add", "a.txt")
        self.fake_bin = Path(self.tmp.name) / "slow-git-bin"
        self.fake_bin.mkdir()

    def install_slow_git(self, slow_subcommands):
        """A git wrapper that hangs on the given subcommands and runs the real git otherwise."""
        real_git = shutil.which("git", path=self.env.get("PATH"))
        cases = "|".join(slow_subcommands)
        script = self.fake_bin / "git"
        script.write_text("#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in %s) exec sleep 60;; esac; done\n"
                          "exec %s \"$@\"\n" % (cases, real_git))
        script.chmod(0o755)
        return {"PATH": "%s%s%s" % (self.fake_bin, os.pathsep, self.env.get("PATH", ""))}

    def evaluate_with_budget(self, command, env, seconds):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.repo)}
        environ = dict(self.env)
        environ.update(env)
        with mock.patch.dict(os.environ, environ, clear=True):
            start = time.monotonic()
            out = g.evaluate(payload, deadline=time.monotonic() + seconds)
            return out, time.monotonic() - start

    @unittest.skipUnless(os.name == "posix", "needs a shell script as fake git")
    def test_slow_diff_is_cut_at_the_deadline_and_asks(self):
        env = self.install_slow_git(["diff", "ls-files"])
        out, elapsed = self.evaluate_with_budget('git add -A && git commit -m "wip"', env, 1.0)
        self.assertLess(elapsed, 2.5)
        self.assertDecision(out, "ask")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("staged diff: scan time limit reached", reason)
        self.assertIn("unstaged diff: scan time limit reached", reason)
        self.assertIn("untracked files: scan time limit reached", reason)

    @unittest.skipUnless(os.name == "posix", "needs a shell script as fake git")
    def test_slow_repository_lookup_asks_instead_of_skipping(self):
        env = self.install_slow_git(["rev-parse"])
        out, elapsed = self.evaluate_with_budget('git commit -m "wip"', env, 1.0)
        self.assertLess(elapsed, 2.5)
        self.assertDecision(out, "ask")
        self.assertIn("git did not answer in time", out["hookSpecificOutput"]["permissionDecisionReason"])

    @unittest.skipUnless(os.name == "posix", "needs a shell script as fake git")
    def test_whole_run_stays_below_the_hook_timeout(self):
        hook = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
        env = self.install_slow_git(["diff", "ls-files"])
        start = time.monotonic()
        code, out, _ = self.run_hook("Bash", {"command": 'git add -A && git commit -m "wip"'}, env=env)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, hook["timeout"] - 2)
        self.assertEqual(code, 0)
        self.assertDecision(out, "ask")
        self.assertIn("scan time limit reached", out["hookSpecificOutput"]["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
