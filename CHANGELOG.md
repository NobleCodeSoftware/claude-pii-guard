# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.4] - 2026-11-06

### Fixed

- Content that a command line commits from outside the index was not scanned, so these commits
  passed without a finding or a prompt:
  - `git add PATHS && git commit`: untracked files under the given paths (only `-A`, `--all`, `.`,
    `*` and `:/` were covered before). They are now listed with
    `git ls-files --others --exclude-standard` (without `--exclude-standard` for `git add -f`) and
    scanned. Unstaged changes to tracked files are scanned only under the given paths.
  - `git commit PATHS` (also with `-i`/`--include` or `-o`/`--only`): the working-tree version of
    the given paths is committed, but only the staged diff was read. The unstaged changes under
    those paths are now scanned.
  - `git stage`, the built-in synonym of `git add`, was not recognised at all: `git stage PATHS`
    and `git stage -A` before `git commit` are now handled exactly like `git add`.
- `git add -f -A` and `git add -f .` now also scan ignored files, which git adds in that case.
- Unstaged changes are no longer read with `git diff` against the working tree, which runs the
  clean filters (`filter.<driver>.clean` and `.process`) named in a repository's git config and
  `.gitattributes`, so such a program could run before the user approved the command. The hook now
  lists the index with `git ls-files -s`, reads changed working-tree files itself and compares them
  line by line with the staged blob from `git cat-file blob`, which runs no filter.
- A `cd` that may not take effect (inside a subshell, `bash -c '...'`, a condition, a loop, a
  `case` branch, a function that is not called, a pipeline or a background job) was always
  followed, so later `git add` and `git commit` paths could be resolved in the wrong directory and
  nothing was scanned. Relative paths are now resolved against every directory the command may
  change into: the starting directory and every existing directory reachable through any `cd`,
  `pushd` or `git -C` in the command line. The scan can be wider than what git will add, never
  narrower. A directory that cannot be resolved (an expansion, `cd -`, a `popd` without `pushd`, a
  directory that does not exist yet, `CDPATH` set for a relative `cd`) makes the whole of every
  repository involved count, and the user is asked.
- The tokenizer returned `);`, `)|`, `)&` and `))` as single words, so they did not end a
  subshell or a command. Runs of shell punctuation are now split into separate operators.
- With several `git commit` commands in one command line, only the staged diff of the first one's
  repository was scanned. The staged diff of every repository found as above is now scanned.
- Arguments of `git add` and `git commit` that follow a message split again as a command line (for
  example `git commit -m "$(cat <<'EOF' ... EOF)" PATHS`) are now read as arguments of that command.

### Changed

- The arguments of `git add` and `git commit` are classified as options, option values and
  pathspecs. When they cannot be classified (a path with a variable, a command substitution, a brace
  expansion or `~`, an unknown option, `--pathspec-from-file`, arguments supplied by `xargs` or
  `parallel`, a directory that does not exist yet), the unstaged changes and untracked files of the
  whole repository are scanned and the user is asked. After a here-document operator, where the
  document's body cannot be told from arguments, such a word makes the whole repository count
  without a prompt.
- New git calls use the same hardening as the existing ones (no shell, fixed argument list, paths
  after `--`, external diff, textconv and fsmonitor disabled, `GIT_OPTIONAL_LOCKS=0`, the shared
  deadline). A line of the working-tree file that also appears in the staged version is not reported
  again, and a change of line endings alone adds nothing. Every git call also sets
  `diff.relative=false`, so diff paths are relative to the top of the work tree when git runs in a
  subdirectory.
- An untracked file whose real path is outside the repository (a symbolic link pointing out of it)
  is not read; the link text, which is what git commits, is scanned instead.
- A changed tracked file larger than `max_scan_bytes` is reported as not scanned without being
  hashed or read, so it cannot use up the time budget.
- Description in `plugin.json`, `marketplace.json` and the README: "Catches common personal data
  before Claude Code writes or commits it." instead of "Stops Claude Code from writing or committing
  personal data.", which overstated what a pattern-based hook can do.
- README: "What is scanned" lists exactly which working-tree content `git add` and `git commit` are
  scanned for; "Limitations" replaces the claim that the next commit is checked again (content that
  is already committed is not scanned again) with a list of what is not scanned.
- `SECURITY.md`: "Security design" says exactly which git calls are made and that no configured
  diff program, textconv driver, fsmonitor hook or clean filter runs; the last item under "Guidance
  for users" says how reports are handled.

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
