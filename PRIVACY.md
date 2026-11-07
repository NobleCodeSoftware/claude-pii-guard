# Privacy policy

pii-guard is a local Claude Code plugin. It runs as a hook on your own machine, inside your Claude
Code session.

- **No collection.** The plugin does not collect personal data, usage data or telemetry.
- **No sending.** The plugin makes no network connections of its own. The only program it starts is
  `git`, run locally on your repository (in a partial clone, git may download missing objects on its
  own when they are read).
- **No storage.** The plugin writes no files. It reads the text a tool call is about to write or
  commit, and the local files needed for that check, for example the current content of a file
  that is about to be written or edited, untracked files under `git add -A`, a changed file that
  git shows without a text diff, commit message files, and the user and repository configuration
  files. It checks them in memory and prints a decision for Claude Code. Values it reports are
  partly masked: an e-mail address keeps the first character of the local part and of the domain,
  and the top-level domain; a PESEL keeps its last two digits; phone, IBAN and card numbers keep
  their first two and last two characters (only the first character when they are short), and
  their length and separators are visible.
- **Your private phrases.** The optional phrases file is read from your user configuration (by
  default `~/.config/pii-guard/phrases.txt`). pii-guard never sends the file anywhere and never puts
  its content into its output: when a phrase is found, it reports only the phrase's first character,
  with the remaining characters replaced by asterisks (the length is visible). The plugin refuses to
  use the file if it lies inside the repository being scanned. It does not stop the file from being
  committed or from being read by other tools in your Claude Code session, so keep it outside every
  repository.
- **No retention.** pii-guard itself stores nothing and sends nothing, so it has nothing to retain or
  delete. Its messages, with masked values and file paths, become part of your Claude Code session
  (see below). The authors receive no data from the plugin.

Claude Code itself, and the model provider you use with it, have their own privacy terms; the
messages pii-guard shows become part of your Claude Code session like any other tool output.

pii-guard is a technical aid. It does not make you compliant with any data protection law.

Questions: open an issue at https://github.com/NobleCodeSoftware/claude-pii-guard/issues. Issues
are public, so please do not include real personal data.
