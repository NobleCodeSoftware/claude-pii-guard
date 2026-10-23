# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-23

### Changed

- Quoted arguments are split into commands again where another program runs them as a command
  line: `sh -c`, `bash -c` (also `-lc` and similar), `zsh -c` and other shells, `bash <<< '...'`,
  `busybox sh -c`, `su -c`, `find -exec sh -c`, `env -S`, `eval`, `pwsh`/`powershell -Command`,
  command substitution (`$(...)`, backticks), text piped into a shell (`echo '...' | sh`), and git
  subcommands that run commands (`submodule foreach`, `rebase -x`/`--exec`, `bisect run`,
  `filter-branch --*-filter`, `difftool`/`mergetool --extcmd`).
- A quoted argument of a text tool (`grep`, `rg`, `ag`, `ack`, `echo`, `printf`, `jq`, `cat`, `gh`,
  and `git` with a subcommand that only reads data, such as `log` or `config --get`) is not treated
  as a command, so `grep -rn "git commit" README.md` or `git log --grep "git commit"` no longer
  scans the staged changes. This holds only when the command line runs nothing: if it also
  contains a shell, an interpreter, `source`/`.`, `exec`, `eval`, `xargs`, `ssh`, a command word
  that is a path, or a runner the hook follows, the text tools' quoted arguments are split as
  commands (`echo '...' > s.txt && cat s.txt | sh`, `{ echo '...'; } > s; sh s`). Text written to a
  file that looks like a script (`.sh`, `.bash`, `.zsh`, `.ksh`, `.ps1`, `.command`, or no extension) is scanned as a
  commit and asks; writing to `.md`, `.txt` and other data files stays silent.
- A quoted argument of any other program that looks like `git ... commit` or `add` (`python -c`,
  `node -e`, `ssh host "..."`, `awk` or `sed`, or another git subcommand) is scanned as a commit and
  asks, because the hook does not parse it.

### Security

- A commit whose `git` or subcommand comes from a variable, a command substitution or ANSI-C quoting
  (`g=git; $g commit`, `${g} commit`, `git $'\x63ommit'`, `$(which git) commit`, `git -c $X commit`)
  is scanned and asks, because the hook does not expand it.

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
