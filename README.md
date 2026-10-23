# pii-guard for Claude Code

Stops Claude Code from writing or committing personal data. A local PreToolUse hook that detects
emails, phone numbers, PESEL, IBAN and Luhn-valid card numbers, plus your own private phrases kept
outside the repo, in block, ask or warn mode. No network access. Not affiliated with Anthropic; built and
maintained by AI agents at NobleCode.

The hook checks what Claude is about to write (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) or commit
(`git commit` from `Bash` or `PowerShell`). If it finds personal data, it blocks the call (or warns,
or asks you, as you prefer) and tells Claude where the value is, masked.

> Status: early release (v0.1.1). A single Python file using only the standard library, plus tests.
> Read "Limitations" before you rely on it.

## The problem

AI coding agents copy data from wherever they find it: a pasted log, a customer e-mail, a
spreadsheet, your own git config. That data then ends up in fixtures, docs, examples and commit
messages, and from there in a public repository. It is easy to do by accident and hard to undo once
pushed.

Review catches most of it, but review is the last line. pii-guard adds an earlier one: the write or
commit does not happen until the data is replaced with synthetic values or explicitly allowed.

## Install (2 commands, plus optional configuration)

Inside Claude Code:

```
/plugin marketplace add NobleCodeSoftware/claude-pii-guard
/plugin install pii-guard@noblecode
```

Then, in your shell, optionally add your private phrases (names, client codenames, your own address).
This file lives **outside every repository** and is never committed:

```bash
mkdir -p ~/.config/pii-guard && $EDITOR ~/.config/pii-guard/phrases.txt
```

Requirements:

- **Claude Code 2.1.295 or newer.** The hook is declared with `"onFailure": "block"`, which the
  documentation lists as requiring v2.1.295. The documentation does not say how older versions treat
  this field, so older versions are not supported: at best they ignore it and the hook fails open
  (a crash or timeout lets the action through).
- `python3` (3.8 or newer) on `PATH`, and `git` for commit scanning. **Without `python3` every
  `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash` and `PowerShell` call is blocked** (see "If the hook fails").

The plugin works with the defaults; configuration is optional. Run `/reload-plugins` or start a new
session after installing.

From the shell, the same steps are `claude plugin marketplace add NobleCodeSoftware/claude-pii-guard`
and `claude plugin install pii-guard@noblecode`.

## What it detects

| Detector | How | Notes |
|---|---|---|
| `email` | address pattern | `example.com`, `example.org`, `example.net`, `localhost`, GitHub noreply addresses and senders such as `noreply@` and `git@` are allowed by default; `logo@2x.png` is ignored |
| `phone` | international `+` numbers with 8 to 15 digits (E.164); Polish formats such as `500 000 004`, `500-000-005`, `(22) 000 00 03`; a bare 9-digit number only after a word such as `tel`, `phone`, `mobile`, `fax` | |
| `pesel` | 11 digits, checksum **and** a real calendar date (centuries 1800 to 2299) | |
| `iban` | country code, country length table and mod-97 check; also the 26-digit Polish account number (NRB) | |
| `card` | 12 to 19 digits, Luhn check **and** a known network prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro) | |
| `phrases` | case-insensitive match of each line of your private phrases file | never stored in the repository |

Digit detectors do not match inside longer numbers, hashes or identifiers, so version numbers, git
hashes, UUIDs, dates, timestamps and order numbers are not reported. The test suite has a list of
these false-positive cases.

What is scanned:

- `Write`: the whole new content. `NotebookEdit`: the new cell source.
- `Edit` and `MultiEdit`: the new text only. A value that was already in the replaced text is not
  reported again, so you can edit near existing data without noise. Line numbers refer to the file.
- `git commit` (also `git -C dir commit`, `git -C "my repo" commit`, `git -c user.name="A B" commit`,
  `cd dir && git commit`, `pushd dir && git commit`, `/usr/bin/git commit`,
  `bash -c 'git commit ...'`, `sh -c "..."`, `bash <<< '...'`, `busybox sh -c`, `su -c`,
  `find -exec sh -c`, `env -S '...'`, `eval "..."`, `pwsh -Command "..."`, `$(git commit ...)`,
  `echo '...' | sh`, `git submodule foreach '...'`, `git rebase -x '...'`, `git bisect run ...`,
  `git filter-branch --tree-filter '...'`, `git difftool --extcmd '...'`; backslash-newline line
  continuations are joined as bash does, the command is split into shell words and global git
  options are skipped with their values): the staged diff (`git diff --cached`, added lines only),
  the commit command including `-m` messages, and `-F` message files. With `git commit -a` or
  `git add ... && git commit` in the same command, unstaged changes are scanned too, and with
  `git add -A` or `git add .` also untracked files. Commit trailers such as `Signed-off-by:` and
  `Co-authored-by:` are allowed (switch off with `"allow_trailers": false`).
- Quoted text that only mentions `git commit` is not treated as a command when it is an argument
  of a text tool (`grep`, `rg`, `ag`, `ack`, `echo`, `printf`, `jq`, `cat`, `tee`, `gh`), for
  example the pattern in `grep "git commit"`. For `git`, only subcommands that read data count as
  text tools (`log`, `show`, `grep`, `diff`, `status`, `blame`, `shortlog`, `describe`, `rev-parse`,
  `ls-files`, `cat-file`, `help`, `config --get` and similar, plus `commit` for its own message).
  This holds only when the command line runs nothing at all: if it also contains a shell (`sh`,
  `bash`, `zsh`, `dash`, `ksh`, `ash`, `fish`, `busybox`, `pwsh`, `powershell`), `source` or `.`,
  `exec`, `eval`, `xargs`, an interpreter (`python`, `perl`, `ruby`, `node`, `php`, `lua` and
  similar), `ssh`, a command word that is a path (`./s.sh`, `/usr/bin/git`), or a runner the hook
  follows (`find -exec`, `env -S`, `su -c`, `git rebase -x` and the like), the text tools' quoted
  arguments are split as commands. So `echo '...' > s.txt && cat s.txt | sh` and
  `{ echo '...'; } > s; sh s` are scanned as commits. Text written to a file that looks like a script
  (ending in `.sh`, `.bash`, `.zsh`, `.ksh`, `.ps1` or `.command`, or with no extension) may be run by
  a later tool call, so a mention of `git commit` or `add` in it is scanned and asks; writing to
  `.md`, `.txt` and other data files stays silent.

Content that could not be scanned: up to `max_scan_bytes` (default 5 MB) per file, diff or message
is scanned, in 1 MB pieces. The following is **not** allowed silently; in `block` and `ask` mode you
get the permission prompt, in `warn` mode a warning:

- anything beyond `max_scan_bytes`;
- a commit message file (`-F`) that is not a readable regular text file (a FIFO, device, directory,
  binary or unreadable file);
- an untracked file under `git add -A` that cannot be read (no permission, a dangling symlink, a
  FIFO or device);
- a diff or file list that git could not produce;
- a file that git shows without a text diff whose content could not be read (the staged blob for
  the staged diff, the working-tree file for the unstaged diff);
- a command that mentions `git` and then `commit` or `add` as separate words (with no other git
  subcommand such as `log` or `help` in between) when the shell-word parser does not find that
  subcommand, for example because of an unclosed quote or an unknown option: it is scanned as a
  commit in the current directory and you are asked as well;
- a commit whose `git` or subcommand comes from a variable, a command substitution or ANSI-C
  quoting (`g=git; $g commit`, `${g} commit`, `git $'\x63ommit'`, `$(which git) commit`), which the
  hook does not expand: the commit is scanned and you are asked as well. A variable as the command
  word asks only when the command also mentions `git` or `commit`, or uses `$'...'` escapes;
- a quoted argument of any other program that looks like `git ... commit` or `add`
  (`python3 -c "...os.system('git commit')"`, `node -e`, `ssh host "git commit"`, and `awk` or
  `sed`, which can run commands with `system()` or `e`; a git subcommand that does not only read
  data, such as `git tag -m "..."`; text written to a script-like file): the
  hook does not parse those programs, so the commit is scanned and you are asked as well;
- a git alias defined in the command (`git -c alias.<name>=...`, `--config-env alias...`), since it can
  run `commit` under another name: the commit is scanned and you are asked as well;
- a `cd`, `pushd` or `-C` directory before the commit that the hook cannot resolve (it does not
  exist yet, or uses `$`, backticks, globs, `~user` or `cd -`);
- a commit that points git at another repository, work tree or index (`GIT_DIR=`,
  `GIT_WORK_TREE=`, `GIT_INDEX_FILE=`, `--git-dir`, `--work-tree`), which the hook does not follow;
- anything left when the time budget runs out (see below).

When git shows no text diff for a file (because it is binary, or because `.gitattributes` marks it
`-diff` or `binary`), pii-guard reads the content that will be committed: the staged blob
(`git cat-file`) for the staged diff, the working-tree file for the unstaged diff. If that content is
text, the whole file is scanned. Binary files are not scanned for personal data: a file counts as
binary when it has a NUL byte in its first 8 KB. When a commit stages one (in the staged or unstaged
diff, or untracked under `git add -A`), it is listed in a visible note ("binary files skipped, not
scanned for personal data: ..."), and the decision is not changed by it.

Time budget: one hook run has a single 8-second deadline, shared by every `git` call (`rev-parse`,
the staged diff, the unstaged diff, the untracked file list, and two `cat-file` calls per staged file
without a text diff), every file read and the scan itself. Each `git` call gets only the time that is left and is stopped at the
deadline. Whatever is not done by then counts as not scanned, as above. This keeps the hook,
including Python start-up, below its 15-second timeout in `hooks/hooks.json`.

The scan stops after 50 findings, since one is enough for a decision; the message then says
"50 or more findings".

## What you see

In `block` mode (the default) the tool call is denied and Claude gets a message like this:

```
pii-guard: possible personal data in Write to src/users.py.
  - src/users.py, line 2: email address "a***@m***.test"
Replace it with synthetic data (for example user@example.com) or remove it.
Do not add exceptions or allow markers yourself; ask the user.
```

Values are always masked, so the message itself does not repeat the data. The message tells Claude
not to work around the guard, and does not explain how; exceptions are your decision (see
Configuration). You see the same message, with a pointer to this README.

**Changes to the guard itself need your confirmation.** A `Write`, `Edit`, `MultiEdit` or
`NotebookEdit` that adds a new `pii-guard: allow` marker or touches a `pii-guard.json` or anything in
`~/.config/pii-guard/`, and a shell command that mentions `pii-guard.json`, `~/.config/pii-guard` or an
allow marker, always get the permission prompt (`ask`), in every mode.

## Examples

1. **Claude copies a customer row into a test fixture.** It calls `Write` for
   `tests/test_import.py` with `email = "alice@mail.test"`. pii-guard denies the write
   and reports `tests/test_import.py, line 12: email address "a***@m***.test"`. Claude replaces the
   value with `user@example.com` and writes again; this time the call goes through.
2. **A commit that would publish an IBAN.** Claude runs `git add -A && git commit -m "Add invoices"`
   while `data/invoice.csv` (untracked) contains `PL74 0000 0000 0000 0000 0000 0001`. The commit is
   denied with `data/invoice.csv (untracked, staged by git add), line 4: IBAN (Polish account number)`.
3. **Intended data, your exception.** Your project's public support address must stay in the docs.
   You add it yourself to `pii-guard.json` in the repository: `{"allow_values": ["support@example.com"]}`
   (or `"ignore_paths": ["tests/fixtures/**"]` for a folder of synthetic fixtures). If Claude tries to
   make such a change, you get a permission prompt first.

## Configuration

pii-guard reads up to two optional JSON files and merges them:

1. **User config**: `~/.config/pii-guard/pii-guard.json` (or `$XDG_CONFIG_HOME/pii-guard/pii-guard.json`,
   or the path in `PII_GUARD_CONFIG`).
2. **Repository config**: `pii-guard.json` in the repository root. It overrides `mode` and `detectors`
   from the user config and adds to the lists.

Example (`pii-guard.example.json` in this repository):

```json
{
  "mode": "block",
  "detectors": { "email": true, "phone": true, "pesel": true, "iban": true, "card": true, "phrases": true },
  "allow_domains": ["mycompany.example"],
  "allow_values": ["support@example.com"],
  "ignore_paths": ["tests/fixtures/**", "**/*.snap"],
  "allow_markers": ["pii-guard: allow"]
}
```

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"block"` | `block`: deny the tool call. `warn`: allow it and show a warning to you and Claude. `ask`: show the permission prompt so you decide |
| `detectors` | all `true` | turn single detectors off |
| `allow_domains` | see above | e-mail domains that are never reported; a domain covers its subdomains, and a bare label such as `test` covers a top-level domain |
| `allow_local_parts` | `noreply`, `no-reply`, `donotreply`, `do-not-reply`, `git` | e-mail local parts that are never reported |
| `allow_values` | `[]` | exact values to allow (spaces, dashes, dots and case are ignored when comparing). Values in a repository config are public, so keep private ones in the user config |
| `ignore_paths` | `[]` | glob patterns relative to the repository root (`**` matches any depth); a pattern without `/` also matches the file name |
| `allow_markers` | `pii-guard: allow`, `pii-guard:allow` | a line containing a marker is skipped, e.g. `email = "alice@mail.test"  # pii-guard: allow` |
| `allow_trailers` | `true` | skip git trailers in commit messages |
| `phrases_file` | `~/.config/pii-guard/phrases.txt` if it exists | **user config only**; ignored in a repository config |
| `repo_config` | `"full"` | **user config only**: `full`, `lists` (repository may add exceptions but not change `mode` or `detectors`) or `ignore` |
| `max_scan_bytes` | `5000000` | scan limit per file, diff or message; content beyond it is not allowed silently (ask in `block` and `ask` mode, a warning in `warn` mode) |

Environment variables: `PII_GUARD_MODE` (`block`, `warn`, `ask`) overrides the files,
`PII_GUARD_PHRASES` points to a phrases file, `PII_GUARD_CONFIG` to a user config, and
`PII_GUARD_DISABLE=1` switches the hook off for a session.

**Private phrases file**: one phrase per line, `#` starts a comment, phrases shorter than 3 characters
are ignored. If the file is inside the repository being scanned, pii-guard refuses to use it and says
so, because the list itself is sensitive.

You can also scan files by hand or from CI with the same rules. The exit code is 1 when something is
found or a file could not be scanned (over `max_scan_bytes`, unreadable, not a regular file); a binary
file is printed as "binary file skipped, not scanned" and does not change the exit code:

```bash
python3 scripts/pii_guard.py scan path/to/file ...
```

## Limitations (please read)

- **A heuristic, not a guarantee.** Pattern matching misses data it has no pattern for (names, postal
  addresses, dates of birth, national IDs other than PESEL, phone formats of other countries without
  a `+` prefix) and data that is split, encoded or obfuscated. It will also sometimes flag a
  number that only looks like personal data. It does not replace human review before you publish.
- **A guard against accidents, not against a determined agent or user.** New allow markers and
  configuration changes need your confirmation, but data can still be written through a command the
  hook does not inspect (for example `echo ... > file`, `cp`, `curl -o`, a script, or a tool from an
  MCP server). Only file tools and `git commit` are scanned for data.
- **Only `git commit` is inspected.** Other git commands that create commits are not: `git merge`,
  `git cherry-pick`, `git rebase`, `git am`, `git stash` and `git commit-tree`. Neither are shell
  aliases, shell functions, git aliases from your git config, or wrapper scripts. `git` hidden
  behind a variable or `$'...'` asks (see "What is scanned"), but other indirection, such as a
  command built from pieces at run time, is not followed.
- **Commands run by other programs are asked about, not parsed.** A `git commit` inside
  `python -c`, `node -e`, `ssh host "..."`, `awk`, `sed` and similar is recognised only by its text: the current
  repository is scanned and you are asked. A commit those programs build from pieces is not seen.
- **Text that mentions `git commit` can count as a commit.** For example a heredoc that writes a
  file containing the words (`cat > notes.md <<EOF ... git commit ... EOF`) is treated as a commit,
  so the staged changes are scanned. A quoted `git commit` in an `awk` or `sed` program, even a plain
  search such as `sed -n '/git commit/p'`, is scanned and asks, because both can run commands.
  And when a command line runs anything (a shell, an interpreter, a path such as `./build.sh` or
  `/usr/bin/git`), every quoted `git commit` in a text tool's arguments is treated as a commit, for
  example `grep "git commit" README.md && bash build.sh`.
- **Commit scanning is best effort.** It reads the staged state when the hook runs. Complex shell
  constructs (aliases, scripts that call `git commit`, `git add` of specific paths) may be scanned
  less precisely; the next commit is checked again.
- **Masked output still hints at the value** (first and last characters). It goes to your Claude
  session, which already has the full value.
- The PreToolUse hook runs only for tool calls in Claude Code. Files you edit yourself and commits you
  make outside Claude Code are not checked; for those, call `scan` from a git pre-commit hook or CI.
- Cloud sessions load plugins differently from your local machine; check the Claude Code
  documentation on what carries over to cloud environments.

## If the hook fails

The hook is declared with `"onFailure": "block"` (Claude Code 2.1.295 or newer). If `python3` is
missing, the script crashes or the hook reaches its 15-second timeout, Claude Code **blocks** the tool
call instead of letting it through. Because the hook matches `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `Bash` and `PowerShell`, a broken installation blocks **all** of those calls, and the
error names `pii-guard`.

The way out is `/plugin disable pii-guard` (or `claude plugin disable pii-guard` in your shell), then
fix the cause (install `python3`, update the plugin) and enable it again. The environment variable
`PII_GUARD_DISABLE=1` does not help in this situation, because it is read by the Python script that
cannot run.

## Security and privacy

The hook reads JSON from stdin and the files and diffs it needs, matches them with regular
expressions and prints a decision. It does **not** execute or evaluate anything from the scanned
content, does **not** use the network, and sends nothing anywhere. The only program it starts is
`git`, with a fixed argument list, no shell, and external diff drivers, textconv filters and fsmonitor
switched off. See `SECURITY.md`.

## Compatibility

Verified on **2026-10-22** against the Claude Code documentation at code.claude.com/docs (Hooks
reference: `PreToolUse` input on stdin, exit codes, `hookSpecificOutput.permissionDecision`
`deny`/`ask`; Plugins: `.claude-plugin/plugin.json`, `hooks/hooks.json`, `${CLAUDE_PLUGIN_ROOT}`, exec
form with `args`; Plugin marketplaces: `.claude-plugin/marketplace.json`, relative source `"."`) and
with `claude plugin validate --strict` and a local `claude plugin marketplace add` / `claude plugin install` on
Claude Code 2.1.308. `onFailure` was checked in the hooks reference and in the Claude Code changelog
(added in 2.1.295). Hook formats change; if something stops working, check the current
documentation first.

The hook answers with exit code 0 and a JSON object: `permissionDecision: "deny"` (block),
`"ask"` (ask, unscanned content, changes to the guard), or only `systemMessage` and
`additionalContext` (warn). Invalid input (not JSON, `tool_input` not an object) exits with 1 and a
one-line message on stderr; with `onFailure: "block"` Claude Code then blocks the call.

## Development

```bash
python3 -m unittest discover -s tests -v
claude plugin validate .
```

Tests use synthetic data only (`tests/synthetic.py`). `tests/test_repo_clean.py` scans this whole
repository with the plugin's own detectors and fails on any value that is not on the synthetic list.
In CI you can add your own forbidden phrases without writing them into the repository:
`PII_GUARD_FORBIDDEN="phrase one,phrase two"` (from a CI secret).

## Related

- [Agent Business Kit](https://github.com/NobleCodeSoftware/agent-business-kit): conventions and tools
  for running a micro-business with AI agents on Claude Code routines.

## Contributing, security, license

Issues and pull requests are welcome; please use synthetic data only in examples and tests. See
`SECURITY.md`, `CHANGELOG.md` and `LICENSE` (MIT).

This is an independent community project. "Claude" and "Claude Code" are products of their respective
owner; this plugin is not affiliated with, endorsed or sponsored by Anthropic.

---
An experiment by NobleCode, run with the participation of AI. The code, tests and documentation were
written by AI agents and reviewed by a separate AI agent before release.
