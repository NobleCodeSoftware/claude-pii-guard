# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-10-23

### Changed

- Documentation only; the hook's behaviour is unchanged.
- `PRIVACY.md`: which local files the hook reads, and exactly what the masked reports keep.
- README: "What is scanned" is a section heading, so the cross-references to it work; the list of
  git variables that point to another repository includes `GIT_OBJECT_DIRECTORY` and
  `GIT_COMMON_DIR`; the exceptions are listed in "Configuration"; the masking limitation describes
  each detector; the Compatibility check date is 2026-10-23.

## [0.1.2] - 2026-10-23

Preparation for the Claude plugin directory. The hook's behaviour is unchanged.

### Added

- `PRIVACY.md`: the plugin runs locally and collects, sends and stores no data.
- `plugin.json`: `documentationUrl`, `supportUrl` and `privacyPolicyUrl` for the directory listing.

### Changed

- The icon moved from `.claude-plugin/` to `assets/icon.png`, since the documentation keeps only
  the manifests in `.claude-plugin/`.
- `plugin.json` keywords: `gdpr` replaced by `personal-data`; the plugin does not provide
  compliance with any law.
- README: a shorter "What is scanned" section, wrapped lines, a cross-reference between the data
  file rule and the heredoc limitation, and a limitation for scripts written by an earlier tool
  call (also when read through a file descriptor). Several shell examples in the README and this
  changelog are now described in words instead of shell snippets.

## [0.1.1] - 2026-10-23

### Changed

- A command line passed to another program is split into commands again and checked: shells with
  `-c` or a here-string, `busybox`, `su -c`, `find -exec`, `env -S`, `eval`, PowerShell
  `-Command`, command substitution, text piped into a shell, and git subcommands that run commands
  (`submodule foreach`, `rebase -x`/`--exec`, `bisect run`, `filter-branch` filters,
  `difftool`/`mergetool --extcmd`).
- Quoted text in a text tool (`grep`, `rg`, `ag`, `ack`, `echo`, `printf`, `jq`, `cat`, `tee`,
  `gh`, and `git` with a subcommand that only reads data, such as `log` or `config --get`) is not
  treated as a command, so searching a README for the words "git commit" no longer scans the staged
  changes. This holds only when the command line runs nothing else; if it also starts a shell, an
  interpreter, a remote session, `source`, `exec`, `eval`, `xargs`, a program given by path or one
  of the runners above, the quoted text is checked as commands.
- Text that a text tool writes to a file that looks like a script (`.sh`, `.bash`, `.zsh`, `.ksh`,
  `.ps1`, `.command`, or no extension) is scanned as a commit and asks; writing to `.md`, `.txt`
  and other data files stays silent.
- A quoted `git commit` or `add` in a program the hook does not parse (an interpreter's inline code,
  a remote shell command, `awk`, `sed`, or a git subcommand that does not only read data) is scanned
  as a commit and asks.

### Security

- A commit whose `git` or subcommand comes from a shell variable, a command substitution or ANSI-C
  quoting is scanned and asks, because the hook does not expand it.

### Fixed

- README: the list of tools that are blocked without `python3` now includes `MultiEdit` and
  `NotebookEdit`.

## [0.1.0] - 2026-10-22

### Added

- `PreToolUse` hook for `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, and `git commit` run through
  `Bash` or `PowerShell`: the staged diff, the commit message and `-F` message files, plus unstaged
  and untracked files when the same command runs `git add` or `git commit -a`.
- Detectors: e-mail, phone (E.164 and Polish formats), PESEL (checksum and date), IBAN (mod-97 and
  country length, plus Polish NRB), payment cards (Luhn and network prefix), and private phrases
  from a file outside the repository.
- Modes `block`, `warn` and `ask`; exceptions by domain, local part, exact value, path glob, inline
  marker and commit trailer; user and repository configuration with `repo_config` control.
- `scan` command for CI and git hooks.
- Plugin manifest, hooks file and a marketplace in the repository root.
- Tests on synthetic data: checksums, false positives, configuration, hook integration (JSON on
  stdin, decision and exit code), and a scan of the repository against the synthetic list.

### Security

- The hook is declared with `onFailure: "block"` (requires Claude Code 2.1.295): a crash or timeout
  blocks the call. Malformed `tool_input` exits 1 without a traceback.
- Scanning is linear in the input size and stops after 50 findings. One 8-second deadline is shared
  by all git calls, file reads and scanning, so the hook stays below its 15-second timeout.
- Content that could not be scanned asks (or warns in `warn` mode) instead of passing: content over
  `max_scan_bytes` (default 5 MB, scanned in 1 MB pieces), unreadable files, and anything left at
  the deadline.
- Binary files are listed in a visible note as skipped. A staged file that git shows without a text
  diff (binary, or `-diff` in `.gitattributes`) is read from the index and scanned if it is text.
- `git commit` and `git add` are found from shell words: after a path (`/usr/bin/git`) or a quote,
  inside `bash -c`/`sh -c`, with quoted or escaped option values (`git -C "my repo"`,
  `git -c user.name="A B"`) and across backslash-newline continuations. `cd`, `pushd` and `-C` are
  followed.
- The user is asked when the command:
  - still looks like `git ... commit` or `add` but cannot be parsed;
  - defines a git alias (`-c alias.*`);
  - uses a commit directory that cannot be resolved;
  - points git at another repository, work tree or index (`GIT_DIR`, `GIT_WORK_TREE`,
    `GIT_INDEX_FILE`, `--git-dir`, `--work-tree`).
- New allow markers and changes to pii-guard's configuration always ask the user.
- `-F` message files and other files are read only if they are regular files, and are checked
  again on the open descriptor before reading.
