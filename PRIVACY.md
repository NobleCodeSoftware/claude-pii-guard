# Privacy policy

pii-guard is a local Claude Code plugin. It runs as a hook on your own machine, inside your Claude
Code session.

- **No collection.** The plugin does not collect personal data, usage data or telemetry.
- **No sending.** The plugin makes no network connections. The only program it starts is `git`, run
  locally on your repository.
- **No storage.** The plugin writes no files. It reads the text a tool call is about to write or
  commit, and the local files needed for that check, for example the current content of a file
  that is about to be written or edited, untracked files under `git add -A`, a changed file that
  git shows without a text diff, commit message files, and the user and repository configuration
  files. It checks them in memory and prints a decision for Claude Code. Values it reports are
  partly masked: an e-mail address keeps the first character of the local part and of the domain,
  and the top-level domain; a PESEL keeps its last two digits; phone, IBAN and card numbers keep
  their first two and last two characters (only the first character when they are short), and
  their length and separators are visible.
- **Your private phrases stay with you.** The optional phrases file is read from your user
  configuration (by default `~/.config/pii-guard/phrases.txt`); the file itself never leaves your
  machine. When a phrase is found, pii-guard reports only its first character, with the remaining
  characters replaced by asterisks (the length is visible). The plugin refuses to use the file if
  it lies inside the repository being scanned.
- **No retention.** Nothing is stored or sent, so there is nothing to retain or delete. The authors
  receive no data from the plugin.

Claude Code itself, and the model provider you use with it, have their own privacy terms; the
messages pii-guard shows become part of your Claude Code session like any other tool output.

Questions: open an issue at https://github.com/NobleCodeSoftware/claude-pii-guard/issues. Issues
are public, so please do not include real personal data.
