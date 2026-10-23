# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-22

### Added

- `PreToolUse` hook for `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, and `git commit` run through
  `Bash` or `PowerShell` (staged diff, commit message, `-F` message files; unstaged and untracked
  files when the same command runs `git add` or `git commit -a`).
- Detectors: e-mail, phone (E.164 and Polish formats), PESEL (checksum and date), IBAN (mod-97 and
  country length, plus Polish NRB), payment cards (Luhn and network prefix), private phrases from a
  file outside the repository.
- Modes `block`, `warn` and `ask`; exceptions by domain, local part, exact value, path glob, inline
  marker and commit trailer; user and repository configuration with `repo_config` control.
- `scan` command for CI and git hooks.
- Plugin manifest, hooks file and a marketplace in the repository root.
- Hardening: linear-time scanning with a 50-finding stop and one 8 s deadline shared by all git
  calls, file reads and scanning; content over `max_scan_bytes` (default 5 MB, scanned in 1 MB
  pieces), unreadable files and anything left at the deadline ask instead of passing; binary files
  are listed as skipped, and a staged file without a text diff (binary or `-diff` in
  `.gitattributes`) is checked in its staged form and scanned if it is text; `git commit` and
  `git add` are found from shell words, so quoted or escaped option values (`git -C "my repo"`,
  `git -c user.name="A B"`) and backslash-newline continuations (`git \<newline>commit`) do not hide
  them, and `pushd` is followed like `cd`; text that still looks like `git ... commit` or `add`, a
  command that cannot be parsed, a git alias defined with `-c alias.*`, a commit directory that
  cannot be resolved, or one that points git at another repository or index (`GIT_DIR`,
  `GIT_INDEX_FILE`, `--git-dir`, `--work-tree`) asks;
  files are re-checked on the open descriptor before reading;
  `onFailure: "block"` (requires Claude Code 2.1.295); new allow markers and configuration changes
  ask the user; `git commit` is also found inside `bash -c`/`sh -c`, after a path (`/usr/bin/git`) or
  a quote; `-F` reads only regular files; malformed `tool_input` exits 1 without a traceback.
- Tests on synthetic data: checksums, false positives, configuration, hook integration (JSON on
  stdin, decision and exit code), and a scan of the repository against the synthetic list.
