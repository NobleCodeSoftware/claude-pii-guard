# pii-guard for Claude Code

Checks Claude Code file edits and git commits for common personal data before they run. A local
PreToolUse hook that detects emails, phone numbers, PESEL, IBAN and Luhn-valid card numbers, plus
your own private phrases from a file outside the repository, in block, ask or warn mode. It makes no
network connections of its own. Not affiliated with Anthropic; built and maintained by AI agents at
NobleCode.

The hook checks what Claude is about to write with a file tool (`Write`, `Edit`, `MultiEdit`,
`NotebookEdit`) or commit (`git commit` from `Bash` or `PowerShell`). If it finds personal data, it
blocks the call (or warns, or asks you, as you prefer) and tells Claude where the value is, masked.
Other shell commands are not scanned for data: a file written with `>`, a heredoc, `cp` or `sed -i`
is checked only when a later `git commit` takes it.

> Status: early release (v0.1.5). A single Python file using only the standard library, plus tests.
> Read "Limitations" before you rely on it.

## The problem

AI coding agents copy data from wherever they find it: a pasted log, a customer e-mail, a
spreadsheet, your own git config. That data then ends up in fixtures, docs, examples and commit
messages, and from there in a public repository. It is easy to do by accident and hard to undo once
pushed.

Review catches most of it, but review is the last line. pii-guard adds an earlier one: in the
default `block` mode, a file-tool write or `git commit` in which it finds such data is denied until
the data is replaced or you add an exception. In `ask` mode you decide in the permission prompt; in
`warn` mode the call goes through with a warning. pii-guard is a technical aid; it does not make you
compliant with any data protection law.

## Install (2 commands, plus optional configuration)

Inside Claude Code:

```
/plugin marketplace add NobleCodeSoftware/claude-pii-guard
/plugin install pii-guard@noblecode
```

Then, in your shell, optionally add your private phrases (names, client codenames, your own
address). Keep this file **outside every repository**. pii-guard does not use a phrases file inside
the repository it scans, but it does not stop the file from being committed (for example when your
home directory is a dotfiles repository):

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
| `email` | address pattern | `example.com`, `example.org`, `example.net`, `localhost`, GitHub noreply addresses and senders such as `noreply@` and `git@` are allowed by default; `logo@2x.png` is ignored, and so is any address whose domain ends in a file extension such as `.md`, `.py` or `.rs` (also real country domains) |
| `phone` | international `+` numbers with 8 to 15 digits (E.164); Polish formats such as `500 000 004`, `500-000-005`, `(22) 000 00 03`; a bare 9-digit number only after a word such as `tel`, `phone`, `mobile`, `fax` | |
| `pesel` | 11 digits, checksum **and** a real calendar date (centuries 1800 to 2299) | |
| `iban` | country code, country length table and mod-97 check; also the 26-digit Polish account number (NRB) | |
| `card` | 13 to 19 digits, Luhn check **and** a known network prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro) | |
| `phrases` | case-insensitive substring match of each line of your private phrases file (3 or more characters, not starting with `#`), without word boundaries: `Ann` also matches `annual` | read from your user configuration, not from the repository |

Digit detectors do not match fragments of longer numbers, hashes or identifiers, which keeps most
version numbers, git hashes, UUIDs, dates and timestamps out of the report. A standalone number can
still be reported if it looks like a phone number (for example three groups of three digits) or
passes a PESEL, IBAN or card check. The test suite has a list of false-positive cases.

## What is scanned

- `Write`: the whole new content. `NotebookEdit`: the new cell source.
- `Edit` and `MultiEdit`: the new text only. A value that was already in the replaced text is not
  reported again, so you can edit near existing data without noise; private phrases are the
  exception and are reported again. Line numbers are approximate: they point to the first occurrence
  of the replaced text in the file before the edit (line 1 if it is not found).
- `git commit`: the staged diff (added lines only), the whole command line including its `-m`
  messages, and message files given as `-F FILE`, `-FFILE`, `--file FILE` or `--file=FILE` (not
  inside combined flags such as `-aF FILE`; a message file that does not exist yet when the hook runs
  is skipped). Other shell commands are not scanned for data; the hook only checks whether they
  touch pii-guard's configuration (see "What you see"). Commit trailers such as `Signed-off-by:` are allowed (switch off with
  `"allow_trailers": false`).
- Working-tree content that `git add` (or its synonym `git stage`) or `git commit` in the same
  command line takes into the commit, read from the working tree before the command runs:
  - `git add PATHS`: unstaged changes to tracked files and untracked files under those paths
    (ignored files only with `-f`/`--force`); with `-u`, tracked files only;
  - `git add -A` (or `-i`) without paths: the same for the whole repository; `git add -u`, `-p` or
    `-e` without paths: all unstaged changes to tracked files. `.` and `:/` are paths like any
    other; a glob such as `*` or `*.csv` is passed to git, which matches it recursively, so it can
    cover more than the shell would add;
  - `git commit -a`: all unstaged changes to tracked files; `git commit PATHS` (also with `-i` or
    `-o`): unstaged changes under those paths.

  Paths are passed to git exactly as written, after `--`. The hook does not decide which `cd` in a
  command line really runs (one inside a condition, a function, a pipeline, a background job or a
  subshell may or may not), so relative paths are resolved against every directory the command
  may change into: the starting directory and every existing directory reachable through any
  `cd`, `pushd` or `git -C` in the command line. The scan can therefore be wider than what git will
  add. Other ways of changing directory, such as `env -C`, `sudo -D` or PowerShell `Set-Location`,
  are not followed: the starting directory is checked instead, without a prompt, so the scan can
  miss what git adds. Each repository found this way also has its staged diff scanned. Arguments are told apart
  from the
  values of options such as `-m`, `-F`, `-C`, `-c`, `-t`, `--author`, `--date`, `--fixup`,
  `--squash`, `--cleanup` and `--trailer`. When the hook cannot tell which files an argument list
  takes, the unstaged changes and untracked files of the whole repository are scanned and you are
  asked (see below). After a here-document operator (`<<EOF`) the hook cannot tell the document's
  body from arguments, so a path there that it cannot classify makes the whole repository count and
  an unknown option there is skipped, both without a prompt.

  Unstaged changes are found without `git diff`, which would run the clean filters
  (`filter.<driver>.clean` or `.process`) named in the repository's git config and
  `.gitattributes`. The index is listed with `git ls-files -s`; a tracked file whose stat data or
  content hash differs from its index entry is read directly and compared, line by line, with the
  staged blob (`git cat-file blob`). Lines that are not in the staged version are scanned, as they
  are in the working tree: no filter output is scanned, and a change of line endings alone adds
  nothing.

How a commit is found in a shell command:

- The command is split into shell words, line continuations are joined, and global git options
  (`-C`, `-c`, `--no-pager` and others) are skipped with their values. `cd`, `pushd`, `popd` and
  `-C` are followed to the repository, and the paths of `git add` and `git commit` are resolved
  in every directory the command may change into (see above).
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
- A quoted `git commit` or `git add` that a text tool writes to a file that looks like a script
  (`.sh`, `.bash`, `.zsh`, `.ksh`, `.ps1`, `.command`, or no extension) may be run later, so it is
  treated as a commit and asks. Other text written to such a file is not scanned. Writing to `.md`,
  `.txt` and other data files with `echo`, `printf` or `tee` stays silent; a heredoc is different
  (see "Limitations").

Content that could not be scanned: up to `max_scan_bytes` (default 5 MB) per file, diff or message
is scanned, in 1 MB pieces. The following is **not** allowed silently; in `block` and `ask` mode you
get the permission prompt, in `warn` mode a warning:

- anything beyond `max_scan_bytes`;
- a commit message file (`-F`) that is not a readable regular text file;
- an untracked file taken by `git add` that cannot be read (no permission, a dangling symlink, a
  FIFO or device);
- a diff or file list that git could not produce (for example for a path outside the repository),
  or a file without a text diff whose content could
  not be read;
- anything left when the time budget runs out (see below).

Exceptions, where the call goes through with at most a note, in every mode:

- the commit directory is not a git repository when the hook runs, or git cannot run: only the
  command line and existing `-F` message files are scanned, and without a finding the call is
  allowed with a note. For example
  `git init && git add -A && git commit -m init` in a directory that is not yet a repository commits
  every file without a scan;
- a message file (`-F`) that does not exist when the hook runs is skipped;
- a missing or unreadable private phrases file (also one named in `PII_GUARD_PHRASES`) switches
  phrase detection off without a message (a file that is not valid UTF-8 is different: see
  "Private phrases file" below);
- a configuration file that is not valid JSON is ignored with a note: a broken user config means
  the defaults apply (its `repo_config` setting is lost too), and a broken repository config leaves
  the user config in effect.

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
  a glob, `~user` or `cd -`), a `popd` has no matching `pushd`, or `CDPATH` is set (in the
  environment or in the command) for a relative `cd`. The unstaged changes and untracked files of
  every repository involved are then scanned too;
- the command points git at another repository, work tree or index (the `GIT_DIR`,
  `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` or `GIT_COMMON_DIR` variables,
  `--git-dir`, `--work-tree`);
- the hook cannot tell which files `git add` or `git commit` takes: a path with a variable, a
  command substitution, a brace expansion or `~`; an option it does not know; paths read from a file
  (`--pathspec-from-file`) or supplied by `xargs` or `parallel`; a `git add` directory that does not
  exist yet.

When git shows no text diff for a file (because it is binary, or because `.gitattributes` marks it
`-diff` or `binary`), pii-guard reads the content that will be committed: the staged blob (`git
cat-file`) for the staged diff. If that content is text, the whole file is scanned. Binary files are
not scanned for personal data: a file counts as binary when it has a NUL byte in its first 8 KB.
When a commit stages one (in the staged diff, as a changed tracked file in the working tree, or
untracked and taken by `git add`), it is listed in a visible note ("binary files skipped, not
scanned for personal data: ..."), and the decision is not changed by it.

Time budget: one hook run has a single 8-second deadline, shared by every `git` call (`rev-parse`,
the staged diff, the index listings, the untracked file lists, two `cat-file` calls per staged file
without a text diff, and one per changed tracked file in the working tree), every file read and the
scan itself. Each `git` call gets only the time that is left and is stopped at the deadline.
Whatever is not done by then counts as not scanned, as above. This is designed to keep the hook,
including Python start-up, below its 15-second timeout in `hooks/hooks.json`. Reading the
configuration and phrases files, and reading the current file for a `Write` or `Edit`, are not
covered by the deadline.

Content from the tool call itself (`Write`, `Edit`, the command line) is limited by `max_scan_bytes`
counted in characters. The scan runs in 1 MB pieces cut at line ends, so a value in a single line
longer than that (for example minified JSON) can be split between two pieces and missed.

The scan stops after 50 findings, since one is enough for a decision; the message then says
"50 or more findings". The message lists at most 20 findings and 10 reasons why content could not be
scanned.

## What you see

In `block` mode (the default) the tool call is denied and Claude gets a message like this:

```
pii-guard: possible personal data in Write to src/users.py.
  - src/users.py, line 2: email address "a***@m***.test"
Replace it with synthetic data (for example user@example.com) or remove it.
Do not add exceptions or allow markers yourself; ask the user.
```

Detected values are masked, so the message does not repeat them. File paths and command arguments
in the message are shown as they are; file names are not scanned. The message tells Claude
not to work around the guard, and does not explain how; exceptions are your decision (see
Configuration). You see the same message, with a pointer to this README.

How each mode decides:

| Mode | Personal data found | Content that could not be scanned | Change to the guard (below) |
|---|---|---|---|
| `block` | denied, even if the other two also apply | permission prompt | permission prompt |
| `ask` | permission prompt | permission prompt | permission prompt |
| `warn` | allowed with a warning | allowed with a warning | permission prompt |

In `warn` mode a finding or unscanned content together with a change to the guard also gets the
permission prompt. In `block` mode a finding cannot be approved in a prompt: replace the value, add an
exception to the configuration or change the mode.

**Changes to the guard itself need your confirmation.** A `Write`, `Edit`, `MultiEdit` or
`NotebookEdit` that adds a new `pii-guard: allow` marker or touches a `pii-guard.json` or anything
in `~/.config/pii-guard/`, and a shell command that mentions `pii-guard.json`, `~/.config/pii-guard`
or an allow marker, get the permission prompt (`ask`) in every mode, as far as the hook recognises
them: the name `pii-guard.json` is compared without regard to case, but for file tools the user
config directory (`~/.config/pii-guard/`) is compared with case, so on a case-insensitive file system
a path spelled in another case is not recognised; a marker assembled from pieces at run time is not
recognised, `PII_GUARD_DISABLE=1` in the environment switches the hook off,
and changes to Claude Code's own settings (which can disable the plugin) are not covered.

## Examples

1. **Claude copies a customer row into a test fixture.** It calls `Write` for
   `tests/test_import.py` with `email = "alice@mail.test"`. pii-guard denies the write
   and reports `tests/test_import.py, line 12: email address "a***@m***.test"`. Claude replaces the
   value with `user@example.com` and writes again; this time the call goes through.
2. **A commit that would publish an IBAN.** Claude runs `git add -A && git commit -m "Add invoices"`
   while `data/invoice.csv` (untracked) contains `PL74 0000 0000 0000 0000 0000 0001` on line 4. The
   commit is denied with
   `data/invoice.csv (untracked, staged by git add), line 4: IBAN "PL** **** **** **** **** **** **01"`.
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
2. **Repository config**: `pii-guard.json` in the repository root. It overrides `mode`,
   `detectors`, `allow_trailers` and `max_scan_bytes` from the user config and adds to the lists.
   With the default `"repo_config": "full"`, a repository you clone can therefore switch detectors
   off, set `warn` or ignore every path without a prompt (only changes that Claude makes ask). For
   repositories you do not trust, set `"repo_config": "ignore"` in your user config.

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
| `phrases_file` | `phrases.txt` in the user config directory (see above), if it exists | **user config only**; ignored in a repository config |
| `repo_config` | `"full"` | **user config only**: `full`, `lists` (repository may add exceptions but not change `mode` or `detectors`) or `ignore` |
| `max_scan_bytes` | `5000000` | scan limit per file, diff or message; content beyond it is not allowed silently (ask in `block` and `ask` mode, a warning in `warn` mode) |

Environment variables: `PII_GUARD_MODE` (`block`, `warn`, `ask`) overrides the files,
`PII_GUARD_PHRASES` points to a phrases file, `PII_GUARD_CONFIG` to a user config, and
`PII_GUARD_DISABLE=1` switches the hook off for a session.

**Private phrases file**: UTF-8 text without a byte order mark, one phrase per line, `#` starts a
comment, phrases shorter than 3 characters are ignored. A file that is not valid UTF-8 makes the hook
fail with "invalid hook input", and because of `"onFailure": "block"` every matched tool call is then
blocked until you fix the file (see "If the hook fails"). A byte order mark at the start becomes part
of the first phrase, which then never matches. If the file is inside the repository being scanned, pii-guard refuses to use
it and says so, because the list itself is sensitive.

You can also scan files by hand or from CI with the same rules. The exit code is 1 when something
is found or a file could not be scanned (over `max_scan_bytes`, unreadable, not a regular file); a
binary file is printed as "binary file skipped, not scanned" and does not change the exit code:

```bash
python3 scripts/pii_guard.py scan path/to/file ...
```

`scan` takes files, not directories (a directory counts as not scanned, exit code 1), reads them from
the working tree (so in a git pre-commit hook it checks the working-tree version, not the staged
one) and does not scan commit messages.

## Limitations (please read)

- **A heuristic, not a guarantee.** Pattern matching misses data it has no pattern for (names,
  postal addresses, dates of birth, national IDs other than PESEL, phone formats of other countries
  without a `+` prefix) and data that is split, encoded or obfuscated. It will also sometimes flag a
  number that only looks like personal data. It does not replace human review before you publish,
  and it does not make you compliant with any data protection law.
- **Binary files are not scanned.** A file with a NUL byte in its first 8 KB is skipped with a note,
  and that covers common carriers of personal data such as `.xlsx`, `.docx`, `.pdf` and images.
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
- **Commit scanning sees the repository as it is before the command runs.** The hook runs once,
  before the whole shell command, and scans the staged diff and the working-tree content described
  in "What is scanned". It does not see:
  - content that another command in the same line creates or changes before `git add` or
    `git commit` runs, for example a file written by a script, a redirection or `cp`, or content
    staged by `git apply --cached`, `git checkout ... -- PATH`, `git stash pop` or
    `git update-index` between the hook and the commit;
  - content that is already committed. `git commit --amend` keeps the content and, with
    `--no-edit`, the message of the commit it replaces without scanning them again, and `-C`,
    `-c`, `--fixup` and `--squash` reuse text from an existing commit. A value that slipped into
    an earlier commit is not reported by later commits; it stays in the history until the history
    is rewritten;
  - files inside a nested repository or submodule;
  - commits made by shell aliases, shell functions, git aliases from your git config or scripts
    (see above).
- **Masked output still hints at the value.** An e-mail address keeps the first character of the
  local part and of the domain, and the top-level domain; a PESEL keeps its last two digits; phone,
  IBAN and card numbers keep their first two and last two characters (only the first character
  when they are short), and their length and separators are visible; a private phrase keeps its
  first character and its length. The output goes to your Claude session, which usually already has
  the full value; for a commit it can show hints of values from files Claude has not read.
- **Reading is not checked.** The hook does not look at tools that read data (`Read`, `Grep` and
  others), so it does not stop the phrases file from being read into the session.
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
content and opens no network connections itself (in a partial clone, git may download missing
objects on its own when the hook reads them). Its only output is the decision for Claude Code, with
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
