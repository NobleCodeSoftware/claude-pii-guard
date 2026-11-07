# Security policy

## Supported versions

Only the latest release (and the default branch) receives security fixes. This is an early-stage
project.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting ("Security" tab -> "Report a vulnerability") on this repository. If that is not available,
open a public issue that says only "security contact requested" with no details, and a maintainer
will arrange a private channel.

Include: what you found, how to reproduce it, the affected files or versions, and the impact you
see. Use synthetic data in your report; never send us real personal data.

## What to expect

- Acknowledgement within 5 working days (best effort; this is a small project).
- An assessment and, where confirmed, a fix or mitigation, and credit in the release notes if you
  wish.
- Coordinated disclosure: please give us a reasonable window (we suggest 90 days) before publishing.

## Scope

In scope:

- `scripts/pii_guard.py`: anything that makes the hook execute content from scanned files, diffs,
  commit messages or configuration; use the network; write files; leak an unmasked value or the
  private phrases list into its output; or hang long enough to stall Claude Code;
- `hooks/hooks.json` and the manifests in `.claude-plugin/`;
- documentation that could lead users into an unsafe setup (for example storing the phrases file
  inside a repository).

Missed detections and false positives are bugs, not vulnerabilities: please report them as normal
issues with synthetic examples. The plugin is a heuristic safety net (see "Limitations" in the
README), so a way to write data past it with a tool it does not inspect is a known limitation, not a
vulnerability.

Out of scope: vulnerabilities in Claude Code, git, Python or GitHub (report those to the vendor),
and misconfiguration of your own installation.

## Security design

- Standard library only; no third-party dependencies to audit or update.
- No network connections of its own. The only subprocess is `git` with a fixed argument list, no
  shell, a timeout, and `--no-ext-diff`, `--no-textconv`, `diff.external=` and `core.fsmonitor=false`. `git diff` is
  run only between the index and `HEAD` (`--cached`), and working-tree files are read by the hook
  itself and compared with the staged blobs (`git cat-file blob`), so the hook runs no external diff
  program, textconv driver, fsmonitor hook or clean filter configured in a repository's git config
  or `.gitattributes`. Tests check this for external diff, textconv and clean filters. The git
  commands are local reads, but in a partial clone git may download missing objects on its own.
- Scanned content is only matched with regular expressions; configuration is parsed with `json`.
- The hook is declared with `onFailure: "block"`: a crash or timeout blocks the action instead of
  letting it through. Scan time grows with the input size and the number of private phrases, and
  the scan stops after 50 findings. One hook run has a single 8 s deadline shared by the `git`
  calls, the reads of scanned files and the scanning, designed to keep it below the 15 s hook
  timeout; reading the configuration and phrases files, and the current file for a `Write` or
  `Edit`, is not covered by it. Content it could not
  scan (over `max_scan_bytes`, unreadable, not a regular file, out of time) leads to a permission
  prompt (a warning in `warn` mode). Exceptions, where the call is allowed with at most a note: the
  commit directory is not a git repository or git cannot run (only the command line and existing
  `-F` message files are scanned), a `-F` message file does not exist when the hook runs, the
  private phrases file is missing or unreadable (phrase detection is then off), or a configuration
  file is not valid JSON (it is ignored with a note). A phrases file that is not valid UTF-8 makes
  the hook fail, which blocks every matched call. Binary files in a commit are not scanned and are listed
  in a visible note; the `scan` command reports them as skipped. Scanned files and commit message
  files are opened only if they are regular files, so a FIFO or device there cannot stall the hook;
  the configuration and phrases files are opened directly, so keep them regular files.
- The deny message tells Claude not to add exceptions itself; new allow markers and changes to
  pii-guard's configuration ask the user in every mode, as far as the hook recognises them (see
  "What you see" in the README for what it does not recognise).
- Detected values in messages are masked (PESEL shows only its last two digits); file paths and
  command arguments are shown as they are. The private phrases file is read only from the user's
  configuration or environment and is refused if it lies inside the repository being scanned; the
  hook does not stop the file from being committed or read by other tools.

## Guidance for users

- Keep the phrases file and any private `allow_values` in `~/.config/pii-guard/`, never in a
  repository.
- Treat the hook as one layer: review diffs before you publish and use your host's secret scanning.
- If personal data was already pushed to a public repository, removing it in a new commit is not
  enough: rewrite the history or delete the repository, rotate anything that works as a credential,
  and check your obligations under data protection law (for example GDPR breach notification).
- If you find a vulnerability, especially one that is actively exploited, report it to us privately
  and promptly (see "Reporting a vulnerability"). We handle vulnerability reports as described
  above.
