# pii-guard for Claude Code

Stops Claude Code from writing or committing personal data. A local PreToolUse hook that detects
emails, phone numbers, PESEL, IBAN and Luhn-valid card numbers, plus your own private phrases kept
outside the repo, in block, ask or warn mode. No network access. Not affiliated with Anthropic;
built and maintained by AI agents at NobleCode.

The hook checks what Claude is about to write (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) or
commit (`git commit` from `Bash` or `PowerShell`). If it finds personal data, it blocks the call (or
warns, or asks you, as you prefer) and tells Claude where the value is, masked.

> Status: early release (v0.1.3). A single Python file using only the standard library, plus tests.
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

Then, in your shell, optionally add your private phrases (names, client codenames, your own
address). This file lives **outside every repository** and is never committed:

```bash
mkdir -p ~/.config/pii-guard
```

and put one phrase per line in `~/.config/pii-guard/phrases.txt` with your editor.

Requirements:

- **Claude Code 2.1.295 or newer.** The hook is declared with `"onFailure": "block"`, which the
  documentation lists as requiring v2.1.295. The documentation does not say how older versions treat
  this field, so older versions are not supported: at best they ignore it and the hook fails open
  (a crash or timeout lets the action through).
- `python3` (3.8 or newer) on `PATH`, and `git` for commit scanning. **Without `python3` every
  `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash` and `PowerShell` call is blocked** (see "If
  the hook fails").

The plugin works with the defaults; configuration is optional. Run `/reload-plugins` or start a new
session after installing.

From the shell, the same steps are
`claude plugin marketplace add NobleCodeSoftware/claude-pii-guard` and
`claude plugin install pii-guard@noblecode`.

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

## What is scanned

- `Write`: the whole new content. `NotebookEdit`: the new cell source.
- `Edit` and `MultiEdit`: the new text only. A value that was already in the replaced text is not
  reported again, so you can edit near existing data without noise. Line numbers refer to the file.
- `git commit`: the staged diff (added lines only), the commit command with its `-m` messages, and
  `-F` message files. With `git commit -a`, or `git add` in the same command, unstaged changes are
  scanned too; with `git add -A` or `git add .` also untracked files. Commit trailers such as
  `Signed-off-by:` are allowed (switch off with `"allow_trailers": false`).

How a commit is found in a shell command:

- The command is split into shell words, line continuations are joined, and global git options
  (`-C`, `-c`, `--no-pager` and others) are skipped with their values. `cd`, `pushd` and `-C` are
  followed to the repository.
- A command line passed to another program is split again and checked the same way: a shell with
  `-c` or a here-string, `eval`, PowerShell `-Command`, command substitution, `find -exec`,
  `env -S`, `su -c`, `busybox`, and git subcommands that run commands (`submodule foreach`,
  `rebase -x`, `bisect run`, `filter-branch` filters, `difftool --extcmd`).
- Quoted text that only mentions `git commit` is not a command when it is an argument of a text
  tool (`grep`, `rg`, `ag`, `ack`, `echo`, `printf`, `jq`, `cat`, `tee`, `gh`, and `git` with a
  subcommand that only reads data, such as `log`, `grep` or `config --get`). This exemption holds
  only when the command line runs nothing else: as soon as it also starts a shell, an interpreter,
  a remote session, `source`, `exec`, `eval`, `xargs`, a program given by path, or one of the
  runners above, the text tools' quoted arguments are checked as commands too.
- Text that a text tool writes to a file that looks like a script (`.sh`, `.bash`, `.zsh`, `.ksh`,
  `.ps1`, `.command`, or no extension) may be run later, so it is scanned and asks. Writing to
  `.md`, `.txt` and other data files with `echo`, `printf` or `tee` stays silent; a heredoc is
  different (see "Limitations").

Content that could not be scanned: up to `max_scan_bytes` (default 5 MB) per file, diff or message
is scanned, in 1 MB pieces. The following is **not** allowed silently; in `block` and `ask` mode you
get the permission prompt, in `warn` mode a warning:

- anything beyond `max_scan_bytes`;
- a commit message file (`-F`) that is not a readable regular text file;
- an untracked file under `git add -A` that cannot be read (no permission, a dangling symlink, a
  FIFO or device);
- a diff or file list that git could not produce, or a file without a text diff whose content could
  not be read;
- anything left when the time budget runs out (see below).

In these cases the commit is scanned as well as possible and you are asked too:

- the command looks like `git ... commit` or `add` but the parser cannot confirm it (an unclosed
  quote, an unknown option);
- `git` or its subcommand comes from a variable, a command substitution or ANSI-C quoting, which the
  hook does not expand;
- a quoted `git commit` or `add` appears in a program the hook does not parse (an interpreter's
  inline code, a remote shell command, `awk` or `sed`, a git subcommand that does not only read
  data, text written to a script-like file);
- the command defines a git alias (`-c alias.<name>=...`);
- a `cd`, `pushd` or `-C` directory cannot be resolved (it does not exist yet, or uses a variable,
  a glob, `~user` or `cd -`);
- the command points git at another repository, work tree or index (the `GIT_DIR`,
  `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` or `GIT_COMMON_DIR` variables,
  `--git-dir`, `--work-tree`).

When git shows no text diff for a file (because it is binary, or because `.gitattributes` marks it
`-diff` or `binary`), pii-guard reads the content that will be committed: the staged blob
(`git cat-file`) for the staged diff, the working-tree file for the unstaged diff. If that content
is text, the whole file is scanned. Binary files are not scanned for personal data: a file counts as
binary when it has a NUL byte in its first 8 KB. When a commit stages one (in the staged or unstaged
diff, or untracked under `git add -A`), it is listed in a visible note ("binary files skipped, not
scanned for personal data: ..."), and the decision is not changed by it.

Time budget: one hook run has a single 8-second deadline, shared by every `git` call (`rev-parse`,
the staged diff, the unstaged diff, the untracked file list, and two `cat-file` calls per staged
file without a text diff), every file read and the scan itself. Each `git` call gets only the time
that is left and is stopped at the deadline. Whatever is not done by then counts as not scanned, as
above. This keeps the hook, including Python start-up, below its 15-second timeout in
`hooks/hooks.json`.

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
`NotebookEdit` that adds a new `pii-guard: allow` marker or touches a `pii-guard.json` or anything
in `~/.config/pii-guard/`, and a shell command that mentions `pii-guard.json`, `~/.config/pii-guard`
or an allow marker, always get the permission prompt (`ask`), in every mode.

## Examples

1. **Claude copies a customer row into a test fixture.** It calls `Write` for
   `tests/test_import.py` with `email = "alice@mail.test"`. pii-guard denies the write
   and reports `tests/test_import.py, line 12: email address "a***@m***.test"`. Claude replaces the
   value with `user@example.com` and writes again; this time the call goes through.
2. **A commit that would publish an IBAN.** Claude runs `git add -A && git commit -m "Add invoices"`
   while `data/invoice.csv` (untracked) contains `PL74 0000 0000 0000 0000 0000 0001`. The commit is
   denied with
   `data/invoice.csv (untracked, staged by git add), line 4: IBAN (Polish account number)`.
3. **Intended data, your exception.** Your project's public support address must stay in the docs.
   You add it yourself to `pii-guard.json` in the repository:
   `{"allow_values": ["support@example.com"]}` (or `"ignore_paths": ["tests/fixtures/**"]` for a
   folder of synthetic fixtures). If Claude tries to make such a change, you get a permission prompt
   first.

## Configuration

Exceptions are yours to set: allowed e-mail domains and local parts, exact values, ignored paths,
inline allow markers and commit trailers. pii-guard reads up to two optional JSON files and merges
them:

1. **User config**: `~/.config/pii-guard/pii-guard.json` (or `pii-guard/pii-guard.json` in the
   directory that `XDG_CONFIG_HOME` names, or the path in `PII_GUARD_CONFIG`).
2. **Repository config**: `pii-guard.json` in the repository root. It overrides `mode` and
   `detectors` from the user config and adds to the lists.

Example (`pii-guard.example.json` in this repository):

```json
{
  "mode": "block",
  "detectors": {
    "email": true, "phone": true, "pesel": true, "iban": true, "card": true, "phrases": true
  },
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

**Private phrases file**: one phrase per line, `#` starts a comment, phrases shorter than 3
characters are ignored. If the file is inside the repository being scanned, pii-guard refuses to use
it and says so, because the list itself is sensitive.

You can also scan files by hand or from CI with the same rules. The exit code is 1 when something
is found or a file could not be scanned (over `max_scan_bytes`, unreadable, not a regular file); a
binary file is printed as "binary file skipped, not scanned" and does not change the exit code:

```bash
python3 scripts/pii_guard.py scan path/to/file ...
```

## Limitations (please read)

- **A heuristic, not a guarantee.** Pattern matching misses data it has no pattern for (names,
  postal addresses, dates of birth, national IDs other than PESEL, phone formats of other countries
  without a `+` prefix) and data that is split, encoded or obfuscated. It will also sometimes flag a
  number that only looks like personal data. It does not replace human review before you publish.
- **A guard against accidents, not against a determined agent or user.** New allow markers and
  configuration changes need your confirmation, but data can still be written through a command the
  hook does not inspect (for example a shell redirection, `cp`, a download tool, a script, or a tool
  from an MCP server). Only file tools and `git commit` are scanned for data.
- **Only `git commit` is inspected.** Other git commands that create commits are not: `git merge`,
  `git cherry-pick`, `git rebase`, `git am`, `git stash` and `git commit-tree`. Neither are shell
  aliases, shell functions, git aliases from your git config, or wrapper scripts. `git` hidden
  behind a variable or ANSI-C quoting asks (see "What is scanned"), but other indirection, such as
  a command built from pieces at run time, is not followed.
- **Scripts written earlier are not read.** A script that an earlier tool call wrote and a later one
  runs is not opened, whether it is run by name, with a shell, or through a file descriptor (for
  example `exec 3< s; sh <&3`). Only text written in the same command line, or to a script-like
  file, is checked.
- **Commands run by other programs are asked about, not parsed.** A `git commit` inside an
  interpreter's inline code (`python -c`, `node -e`), a remote shell command, `awk`, `sed` and
  similar is recognised only by its text: the current repository is scanned and you are asked. A
  commit those programs build from pieces is not seen.
- **Text that mentions `git commit` can count as a commit.** A heredoc that writes the words to a
  file (`cat > notes.md <<EOF ... git commit ... EOF`) is treated as a commit even though the file
  is a data file, unlike `echo` or `printf` into `notes.md` (see "What is scanned"). A quoted
  `git commit` in an `awk` or `sed` program, even a plain search such as `sed -n '/git commit/p'`,
  is scanned and asks, because both can run commands. And when a command line runs anything (a
  shell, an interpreter, a program given by path such as `./build.sh` or `/usr/bin/git`), every
  quoted `git commit` in a text tool's arguments is treated as a commit, for example
  `grep "git commit" README.md && bash build.sh`.
- **Commit scanning is best effort.** It reads the staged state when the hook runs. Complex shell
  constructs (aliases, scripts that call `git commit`, `git add` of specific paths) may be scanned
  less precisely; the next commit is checked again.
- **Masked output still hints at the value.** An e-mail address keeps the first character of the
  local part and of the domain, and the top-level domain; a PESEL keeps its last two digits; phone,
  IBAN and card numbers keep their first two and last two characters (only the first character
  when they are short), and their length and separators are visible; a private phrase keeps its
  first character and its length. The output goes to your Claude session, which already has the
  full value.
- The PreToolUse hook runs only for tool calls in Claude Code. Files you edit yourself and commits
  you make outside Claude Code are not checked; for those, call `scan` from a git pre-commit hook or
  CI.
- Cloud sessions load plugins differently from your local machine; check the Claude Code
  documentation on what carries over to cloud environments.

## If the hook fails

The hook is declared with `"onFailure": "block"` (Claude Code 2.1.295 or newer). If `python3` is
missing, the script crashes or the hook reaches its 15-second timeout, Claude Code **blocks** the
tool call instead of letting it through. Because the hook matches `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `Bash` and `PowerShell`, a broken installation blocks **all** of those calls, and
the error names `pii-guard`.

The way out is `/plugin disable pii-guard` (or `claude plugin disable pii-guard` in your shell),
then fix the cause (install `python3`, update the plugin) and enable it again. The environment
variable `PII_GUARD_DISABLE=1` does not help in this situation, because it is read by the Python
script that cannot run.

## Security and privacy

The hook reads JSON from stdin and the files and diffs it needs, matches them with regular
expressions and prints a decision. It does **not** execute or evaluate anything from the scanned
content and does **not** use the network. Its only output is the decision for Claude Code, with
findings masked (a private phrase shows only its first character), which becomes part of your
Claude Code session like any other tool output. The only program it starts is `git`, with a fixed
argument list, no shell, and external diff drivers, textconv filters and fsmonitor switched off.
See `SECURITY.md` and `PRIVACY.md`.

## Compatibility

Verified on **2026-10-23** with `claude plugin validate --strict` on Claude Code 2.1.309, and
against the plugin manifest reference at code.claude.com/docs (`plugin.json` fields, including the
directory listing fields). Earlier, on 2026-10-22, against the rest of the Claude Code documentation
(Hooks reference: `PreToolUse` input on stdin, exit codes, `hookSpecificOutput.permissionDecision`
`deny`/`ask`; Plugins: `hooks/hooks.json`, the `CLAUDE_PLUGIN_ROOT` path variable, exec form with
`args`; Plugin marketplaces: `.claude-plugin/marketplace.json`, relative source `"."`) and with a
local `claude plugin marketplace add` / `claude plugin install` on Claude Code 2.1.308. `onFailure`
was checked in the hooks reference and in the Claude Code changelog (added in 2.1.295). Hook formats
change; if something stops working, check the current documentation first.

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
`PII_GUARD_FORBIDDEN="phrase one,phrase two"` (set it in your CI settings).

## Related

- [Agent Business Kit](https://github.com/NobleCodeSoftware/agent-business-kit): conventions and
  tools for running a micro-business with AI agents on Claude Code routines.

## Contributing, security, license

Issues and pull requests are welcome; please use synthetic data only in examples and tests. See
`SECURITY.md`, `PRIVACY.md`, `CHANGELOG.md` and `LICENSE` (MIT).

This is an independent community project. "Claude" and "Claude Code" are products of their
respective owner; this plugin is not affiliated with, endorsed or sponsored by Anthropic.

---
An experiment by NobleCode, run with the participation of AI. The code, tests and documentation were
written by AI agents and reviewed by a separate AI agent before release.
