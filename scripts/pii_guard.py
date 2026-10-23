#!/usr/bin/env python3
"""pii-guard: a Claude Code PreToolUse hook that stops personal data before it is written or committed.

Standard library only. The hook reads the PreToolUse JSON from stdin, scans the text that a tool call
is about to write (Write, Edit, MultiEdit, NotebookEdit) or commit (Bash or PowerShell running
`git commit`), and prints a decision as JSON on stdout.

Safety properties (please keep them when you change this file):
- no network access; the only module that talks to the outside world is `subprocess`, used to run
  `git` with a fixed argument list (no shell) and with external diff drivers, textconv and
  fsmonitor disabled;
- file contents are only read and matched with regular expressions, never executed or evaluated;
- configuration is parsed with `json`, phrases are plain text lines.

Exit codes: 0 with JSON on stdout (or nothing) is the normal path. 1 means the hook itself failed
(bad input). On its own Claude Code treats exit 1 as a non-blocking error, but hooks/hooks.json
declares the hook with `"onFailure": "block"`, so the tool call is blocked. The CLI `scan` mode exits 1
when it finds something or a file could not be scanned, so it can be used from CI or a git pre-commit
hook.

Time budget: one hook run has a single deadline (TIME_BUDGET_SECONDS) shared by every git call, file
read and scan step. Each git call may only use the time that is left, so the run stays well below the
15-second timeout in hooks/hooks.json; whatever is not done by the deadline is reported as not
scanned.
"""

import bisect
import fnmatch
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time

VERSION = "0.1.1"

# Shared deadline for one hook run, in seconds. Keep it well below the "timeout" in hooks/hooks.json
# (15 s), which also has to cover starting Python.
TIME_BUDGET_SECONDS = 8.0

DEFAULT_CONFIG = {
    "mode": "block",  # block | warn | ask
    "detectors": {
        "email": True,
        "phone": True,
        "pesel": True,
        "iban": True,
        "card": True,
        "phrases": True,
    },
    # Domains whose addresses are never reported. A domain also covers its subdomains, and a bare
    # label such as "test" covers a whole top-level domain (add "test" or "invalid" yourself if your
    # fixtures use those reserved names).
    "allow_domains": ["example.com", "example.org", "example.net", "localhost",
                      "users.noreply.github.com"],
    # Local parts of addresses that are never personal (automation senders, git SSH user).
    "allow_local_parts": ["noreply", "no-reply", "donotreply", "do-not-reply", "git"],
    # Exact values to allow (compared without spaces, dashes and dots, case-insensitive).
    "allow_values": [],
    # Glob patterns relative to the repository root: files that are not scanned.
    "ignore_paths": [],
    # A line that contains one of these markers is not scanned.
    "allow_markers": ["pii-guard: allow", "pii-guard:allow"],
    # Skip git trailer lines such as "Signed-off-by:" in commit messages.
    "allow_trailers": True,
    # Path to the private phrases file. Read only from the user configuration or the
    # PII_GUARD_PHRASES environment variable, never from a repository configuration.
    "phrases_file": "",
    # How much of a repository's pii-guard.json is honoured: full | lists | ignore.
    "repo_config": "full",
    "max_scan_bytes": 5000000,
}

LIST_KEYS = ("allow_domains", "allow_local_parts", "allow_values", "ignore_paths", "allow_markers")
MODES = ("block", "warn", "ask")
REPO_CONFIG_NAME = "pii-guard.json"
# A git trailer that ends right before a finding, on the same line (also inside a quoted -m value).
TRAILER_RE = re.compile(r"(?:^|[\s\"'])(?:Co-authored-by|Signed-off-by|Reviewed-by|Acked-by|Tested-by|"
                        r"Reported-by|Suggested-by|Helped-by)\s*:[^\"'\n:]*$", re.I)

# --------------------------------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![\w.%+-])([A-Za-z0-9._%+-]{1,64})@"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-])")
# Asset names such as logo@2x.png look like addresses.
FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "js", "mjs", "cjs", "ts",
             "css", "map", "json", "html", "md", "txt", "py", "rb", "go", "rs"}

# Digit detectors never start or end next to a letter, a digit or a digit group, so fragments of
# hashes, UUIDs, longer numbers and IBANs are not matched.
_NB = r"(?<![A-Za-z0-9])(?<![0-9][ -])"
_NA = r"(?![ -]?[0-9])(?![A-Za-z0-9])"

PESEL_RE = re.compile(_NB + r"([0-9]{11})" + _NA)
CARD_RE = re.compile(_NB + r"([0-9](?:[ -]?[0-9]){12,18})" + _NA)
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2}[0-9]{2}(?:[ ]?[A-Za-z0-9]){11,30})(?![A-Za-z0-9])")
NRB_RE = re.compile(_NB + r"([0-9]{2}(?:[ ]?[0-9]{4}){6})" + _NA)  # Polish account number, 26 digits
PHONE_INTL_RE = re.compile(r"(?<![\w+])(\+[1-9](?:[ .()-]{0,2}[0-9]){7,14})(?![ .-]?[0-9])(?![A-Za-z0-9])")
PHONE_PL_RE = re.compile(
    r"(?<![\w+])(?<![0-9][ .-])("
    r"\(?0?[1-9][0-9]\)?[ -][0-9]{3}[ -][0-9]{2}[ -][0-9]{2}"  # (22) 000 00 03, 22-000-00-02
    r"|[1-9][0-9]{2}[ -][0-9]{3}[ -][0-9]{3}"  # 500 000 004, 500-000-005
    r")(?![ .-]?[0-9])(?![A-Za-z0-9])")
PHONE_KEYWORD_RE = re.compile(
    r"(?i)\b(?:tel|phone|telefon|mobile|mobil|kom|komórka|fax|gsm)\b[^\n0-9]{0,15}"
    r"(?<![0-9])([1-9][0-9]{8})(?![0-9])")

IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24,
    "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


def pesel_valid(digits):
    """Checksum and a real calendar date (months 1-12 +80/+0/+20/+40/+60 for 1800-2299)."""
    if len(digits) != 11 or not digits.isdigit():
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(d) * w for d, w in zip(digits, weights))
    if (10 - total % 10) % 10 != int(digits[10]):
        return False
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    century = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}
    base = (mm - 1) // 20 * 20 if mm >= 1 else -1
    if base not in century:
        return False
    month = mm - base
    if not 1 <= month <= 12:
        return False
    year = century[base] + yy
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return 1 <= dd <= days


def iban_valid(raw):
    iban = re.sub(r"\s", "", raw).upper()
    country = iban[:2]
    if IBAN_LENGTHS.get(country) != len(iban) or not iban[2:4].isdigit():
        return False
    rearranged = iban[4:] + iban[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def luhn_valid(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def card_brand(digits):
    """Return the card network for an issuer prefix and length, or None."""
    n = len(digits)

    def p(k):
        return int(digits[:k])

    if digits[0] == "4" and n in (13, 16, 19):
        return "Visa"
    if n == 16 and (51 <= p(2) <= 55 or 2221 <= p(4) <= 2720):
        return "Mastercard"
    if n == 15 and p(2) in (34, 37):
        return "American Express"
    if 16 <= n <= 19 and (p(4) == 6011 or 644 <= p(3) <= 649 or p(2) == 65):
        return "Discover"
    if 16 <= n <= 19 and 3528 <= p(4) <= 3589:
        return "JCB"
    if 14 <= n <= 19 and (300 <= p(3) <= 305 or p(2) in (36, 38, 39)):
        return "Diners Club"
    if 16 <= n <= 19 and p(2) == 62:
        return "UnionPay"
    if 12 <= n <= 19 and (p(2) == 50 or 56 <= p(2) <= 69):
        return "Maestro"
    return None


def load_phrases(path):
    phrases = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if len(line) >= 3 and not line.startswith("#"):
                    phrases.append(line)
    except OSError:
        return []
    return phrases


class Finding(object):
    __slots__ = ("kind", "value", "line", "start", "end")

    def __init__(self, kind, value, line, start, end):
        self.kind, self.value, self.line, self.start, self.end = kind, value, line, start, end


def _domain_allowed(domain, allowed):
    domain = domain.lower()
    for d in allowed:
        d = d.lower()
        if d.startswith("*."):
            d = d[2:]
        d = d.strip(".")
        if d and (domain == d or domain.endswith("." + d)):
            return True
    return False


def normalize(value):
    return re.sub(r"[\s.\-()]", "", value).lower()


def _candidates(text, config, phrases):
    """All raw matches as (start, priority, end, kind, value). Linear in the size of `text`."""
    det = config["detectors"]
    local_parts = {p.lower() for p in config["allow_local_parts"]}
    raw = []
    if det.get("email"):
        for m in EMAIL_RE.finditer(text):
            local, domain, tld = m.group(1), m.group(2), m.group(3)
            if tld.lower() in FILE_TLDS or local.lower() in local_parts:
                continue
            if _domain_allowed(domain, config["allow_domains"]):
                continue
            raw.append((m.start(), 0, m.end(), "email address", m.group(0)))
    if det.get("iban"):
        for m in IBAN_RE.finditer(text):
            if iban_valid(m.group(1)):
                raw.append((m.start(1), 1, m.end(1), "IBAN", m.group(1)))
        for m in NRB_RE.finditer(text):
            if iban_valid("PL" + re.sub(r"\s", "", m.group(1))):
                raw.append((m.start(1), 1, m.end(1), "IBAN (Polish account number)", m.group(1)))
    if det.get("card"):
        for m in CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(1))
            brand = card_brand(digits)
            if brand and luhn_valid(digits):
                raw.append((m.start(1), 2, m.end(1), "payment card number (%s)" % brand, m.group(1)))
    if det.get("pesel"):
        for m in PESEL_RE.finditer(text):
            if pesel_valid(m.group(1)):
                raw.append((m.start(1), 3, m.end(1), "PESEL", m.group(1)))
    if det.get("phone"):
        for rx, kind in ((PHONE_INTL_RE, "phone number (international)"),
                         (PHONE_PL_RE, "phone number (Polish format)"),
                         (PHONE_KEYWORD_RE, "phone number")):
            for m in rx.finditer(text):
                if rx is PHONE_INTL_RE and not 8 <= len(re.sub(r"[^0-9]", "", m.group(1))) <= 15:
                    continue
                raw.append((m.start(1), 4, m.end(1), kind, m.group(1)))
    if det.get("phrases") and phrases:
        low = text.lower()
        for phrase in phrases:
            pl = phrase.lower()
            pos = low.find(pl)
            while pos != -1:
                raw.append((pos, 5, pos + len(pl), "private phrase", text[pos:pos + len(pl)]))
                pos = low.find(pl, pos + len(pl))
    return raw


def _resolve_overlaps(raw):
    """Keep one candidate per overlapping group, preferring the stronger detector. O(n log n)."""
    raw.sort(key=lambda c: (c[0], c[1]))
    kept = []
    for c in raw:
        if kept and c[0] < kept[-1][2]:
            if c[1] < kept[-1][1]:
                kept[-1] = c
            continue
        kept.append(c)
    return kept


def scan_text(text, config, phrases=(), skip_line=None, limit=None):
    """Return the findings in `text`, at most `limit` of them. Line numbers are 1-based.

    `skip_line(prefix)` gets up to 200 characters between the start of the line and the finding; a
    true result drops the finding (used for commit trailers). Every step is linear or n log n in the
    size of the text, and each line is checked for allow markers at most once."""
    allow_values = {normalize(v) for v in config["allow_values"]}
    markers = [m.lower() for m in config["allow_markers"] if m]
    kept = _resolve_overlaps(_candidates(text, config, phrases))
    if not kept:
        return []
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    marker_cache = {}
    findings = []
    for start, _prio, end, kind, value in kept:
        if normalize(value) in allow_values:
            continue
        line_no = bisect.bisect_right(line_starts, start)
        line_start = line_starts[line_no - 1]
        if markers:
            has_marker = marker_cache.get(line_no)
            if has_marker is None:
                line_end = line_starts[line_no] - 1 if line_no < len(line_starts) else len(text)
                lt = text[line_start:line_end].lower()
                has_marker = marker_cache[line_no] = any(mk in lt for mk in markers)
            if has_marker:
                continue
        if skip_line is not None and skip_line(text[max(line_start, start - 200):start]):
            continue
        findings.append(Finding(kind, value, line_no, start, end))
        if limit is not None and len(findings) >= limit:
            break
    return findings


def iter_chunks(text, size):
    """Split `text` into pieces of about `size` characters at line ends; yield (piece, line_offset)."""
    pos, offset, n = 0, 0, len(text)
    while pos < n:
        stop = min(pos + size, n)
        if stop < n:
            nl = text.rfind("\n", pos, stop)
            if nl > pos:
                stop = nl + 1
        piece = text[pos:stop]
        yield piece, offset
        offset += piece.count("\n")
        pos = stop


def count_markers(text, config):
    low = (text or "").lower()
    return sum(low.count(m.lower()) for m in config["allow_markers"] if m)


def mask(value, kind=""):
    """Show enough to find the value in the file, never enough to reconstruct it."""
    if kind == "private phrase":
        return value[:1] + "*" * max(len(value) - 1, 2)
    if "@" in value:
        local, _, domain = value.partition("@")
        head, dot, tld = domain.rpartition(".")
        return "%s***@%s***%s%s" % (local[:1], head[:1], dot, tld)
    chars = list(value)
    sig = [i for i, c in enumerate(chars) if c.isalnum()]
    if kind == "PESEL":
        keep = set(sig[-2:])  # the first digits encode the date of birth
    elif len(sig) > 6:
        keep = set(sig[:2] + sig[-2:])
    else:
        keep = set(sig[:1])
    return "".join(c if (i in keep or not c.isalnum()) else "*" for i, c in enumerate(chars))


# --------------------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------------------

def _expand(path):
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def user_config_path():
    env = os.environ.get("PII_GUARD_CONFIG")
    if env:
        return _expand(env)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "pii-guard", REPO_CONFIG_NAME)


def _read_json(path, notes):
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("top level must be an object")
        return data
    except (OSError, ValueError) as exc:
        notes.append("config %s ignored: %s" % (path, exc))
        return {}


def _apply(config, data, lists_only=False, notes=None):
    for key in LIST_KEYS:
        if isinstance(data.get(key), list):
            config[key] = config[key] + [str(v) for v in data[key]]
    if lists_only:
        return
    if data.get("mode") in MODES:
        config["mode"] = data["mode"]
    elif "mode" in data and notes is not None:
        notes.append("unknown mode %r ignored" % (data["mode"],))
    if isinstance(data.get("detectors"), dict):
        for k, v in data["detectors"].items():
            if k in config["detectors"]:
                config["detectors"][k] = bool(v)
    if isinstance(data.get("allow_trailers"), bool):
        config["allow_trailers"] = data["allow_trailers"]
    if isinstance(data.get("max_scan_bytes"), int) and data["max_scan_bytes"] > 0:
        config["max_scan_bytes"] = data["max_scan_bytes"]


def find_repo_root(start):
    path = os.path.abspath(start or ".")
    if os.path.isfile(path):
        path = os.path.dirname(path)
    while not os.path.isdir(path):
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent
    while True:
        if os.path.exists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def load_config(repo_root, notes):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    user = _read_json(user_config_path(), notes)
    _apply(config, user, notes=notes)
    if isinstance(user.get("phrases_file"), str):
        config["phrases_file"] = user["phrases_file"]
    if user.get("repo_config") in ("full", "lists", "ignore"):
        config["repo_config"] = user["repo_config"]
    if repo_root and config["repo_config"] != "ignore":
        repo = _read_json(os.path.join(repo_root, REPO_CONFIG_NAME), notes)
        if "phrases_file" in repo:
            notes.append("phrases_file in a repository config is ignored (it belongs in the user config)")
        _apply(config, repo, lists_only=config["repo_config"] == "lists", notes=notes)
    env_mode = os.environ.get("PII_GUARD_MODE", "").strip().lower()
    if env_mode in MODES:
        config["mode"] = env_mode
    return config


def resolve_phrases(config, repo_root, notes):
    path = os.environ.get("PII_GUARD_PHRASES") or config.get("phrases_file") or ""
    if not path:
        default = os.path.join(os.path.dirname(user_config_path()), "phrases.txt")
        path = default if os.path.isfile(default) else ""
    if not path:
        return []
    path = _expand(path)
    if repo_root and _is_within(path, repo_root):
        notes.append("phrases file is inside the repository and was not used; move it out of the repo")
        return []
    return load_phrases(path)


def _is_within(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def glob_to_regex(pattern):
    pattern = pattern.replace("\\", "/").lstrip("/")
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def path_ignored(rel_path, config):
    rel = rel_path.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    for pat in config["ignore_paths"]:
        if glob_to_regex(pat).match(rel) or fnmatch.fnmatchcase(os.path.basename(rel), pat):
            return True
    return False


def relpath(path, repo_root):
    if repo_root and _is_within(path, repo_root):
        return os.path.relpath(os.path.realpath(path), os.path.realpath(repo_root)).replace("\\", "/")
    return path.replace("\\", "/")


# --------------------------------------------------------------------------------------------------
# Sources: what a tool call is about to write
# --------------------------------------------------------------------------------------------------

class Source(object):
    """A block of text with a label and the line number of its first line.

    `unscanned` is a short reason when part of the content could not be scanned (too large,
    unreadable, not a regular file, out of time); the hook then asks the user (or warns in warn mode)
    instead of allowing silently. `binary_skipped` marks a binary file that was skipped; it is listed
    in a visible note but does not change the decision."""

    def __init__(self, label, text, first_line=1, rel_path=None, known=None, skip_trailers=False,
                 unscanned=None, binary_skipped=False):
        self.label, self.text, self.first_line = label, text, first_line
        self.rel_path = rel_path
        self.known = known or set()  # values already present before the edit
        self.skip_trailers = skip_trailers
        self.unscanned = unscanned
        self.binary_skipped = binary_skipped


def _is_regular(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _read_text(path, limit):
    """Return (text, truncated) for a regular text file, or (None, reason) otherwise.

    FIFOs, devices and directories are refused before opening. The file is then opened without
    blocking and checked again on the open descriptor, so swapping it for a FIFO between the two
    checks cannot make the read block."""
    if not _is_regular(path):
        return None, "not a regular file"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "unreadable"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None, "unreadable"
    if b"\0" in data[:8192]:
        return None, "binary"
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def _limited(text, limit):
    text = text or ""
    return (text[:limit], True) if len(text) > limit else (text, False)


def _too_large(limit):
    return "content beyond max_scan_bytes (%d) was not scanned" % limit


TIME_LIMIT_REASON = "scan time limit reached, not scanned"


def _line_of(haystack, needle):
    if not haystack or not needle:
        return 1
    pos = haystack.find(needle)
    return haystack.count("\n", 0, pos) + 1 if pos >= 0 else 1


def file_sources(tool, tin, repo_root, config):
    path = tin.get("file_path") or tin.get("notebook_path") or ""
    rel = relpath(path, repo_root) if path else "(unknown file)"
    limit = config["max_scan_bytes"]
    if tool == "Write":
        text, cut = _limited(tin.get("content"), limit)
        return [Source(rel, text, 1, rel, unscanned=_too_large(limit) if cut else None)]
    if tool == "NotebookEdit":
        text, cut = _limited(tin.get("new_source"), limit)
        return [Source(rel + " (notebook cell)", text, 1, rel, unscanned=_too_large(limit) if cut else None)]
    edits = tin.get("edits") if tool == "MultiEdit" else [tin]
    current = _read_text(path, limit)[0] if path else None
    out = []
    for e in edits if isinstance(edits, list) else []:
        if not isinstance(e, dict):
            continue
        old, _ = _limited(e.get("old_string"), limit)
        new, cut = _limited(e.get("new_string"), limit)
        known = {normalize(f.value) for f in scan_text(old, config)} if old else set()
        out.append(Source(rel, new, _line_of(current, old), rel, known,
                          unscanned=_too_large(limit) if cut else None))
    return out


def marker_added(tool, tin, config):
    """True when a file tool call adds an allow marker that was not there before."""
    path = tin.get("file_path") or tin.get("notebook_path") or ""
    if tool == "Write":
        before = _read_text(path, config["max_scan_bytes"])[0] if path else ""
        return count_markers(tin.get("content"), config) > count_markers(before, config)
    if tool == "NotebookEdit":
        return count_markers(tin.get("new_source"), config) > 0
    edits = tin.get("edits") if tool == "MultiEdit" else [tin]
    for e in edits if isinstance(edits, list) else []:
        if isinstance(e, dict) and count_markers(e.get("new_string"), config) > count_markers(e.get("old_string"), config):
            return True
    return False


def touches_guard_config(path):
    """True for pii-guard's own configuration: any pii-guard.json and the user config directory."""
    if not path:
        return False
    if os.path.basename(path.replace("\\", "/")) == REPO_CONFIG_NAME:
        return True
    return _is_within(_expand(path), os.path.dirname(user_config_path()))


# `git` may follow a space, a shell operator, a quote (bash -c 'git ...'), a slash (/usr/bin/git) or
# a backslash (\git, bypassing aliases).
_GIT = r"(?:^|[\s;&|(`'\"\\/=])git(?:\.exe)?['\"]?"
_GIT_OPTS = r"(?:\s+(?:-C\s+\S+|-c\s+\S+|--[\w-]+(?:=\S+)?|-[A-Za-z]))*"
GIT_COMMIT_RE = re.compile(_GIT + _GIT_OPTS + r"\s+['\"]?commit(?![\w-])")
GIT_ADD_RE = re.compile(_GIT + _GIT_OPTS + r"\s+['\"]?add(?![\w-])([^;&|\n'\"]*)")


# Loose tests for text that looks like `git ... commit` or `git ... add` with both as separate words.
# They are used whenever the token parser did not find that subcommand; the words in between must not
# include another git subcommand, so `git log --grep commit` or `git help commit` do not count.
GIT_LOOSE_RES = {
    sub: re.compile(r"(?<![\w.-])git(?:\.exe)?(?![\w.-])([^;&|\n]*?)(?<![\w.-])%s(?![\w-])" % sub)
    for sub in ("commit", "add")
}
OTHER_GIT_SUBCOMMANDS = {
    "log", "show", "grep", "status", "diff", "help", "blame", "branch", "checkout", "switch", "stash",
    "notes", "tag", "reset", "restore", "revert", "cherry-pick", "rebase", "merge", "pull", "push",
    "fetch", "clone", "init", "config", "rev-list", "rev-parse", "shortlog", "describe", "reflog",
    "bisect", "worktree", "submodule", "remote", "ls-files", "rm", "mv", "clean", "format-patch",
    "am", "apply", "commit", "add",
}
# Global git options that take their value as the next argument.
GIT_VALUE_OPTIONS = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                     "--config-env", "--exec-path")
# Options and variables that make git use another repository, work tree or index than the one the
# hook reads, so the staged state it scans may not be what is committed.
GIT_REDIRECT_OPTIONS = ("--git-dir", "--work-tree")
GIT_REDIRECT_ENV_RE = re.compile(r"(?:^|:)(?:GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_OBJECT_DIRECTORY|"
                                 r"GIT_COMMON_DIR)=")
# A git alias defined on the command line can run `commit` under another name.
GIT_ALIAS_RE = re.compile(r"(?i)(?:^|\s)(?:-c\s*|--config-env[=\s]+)['\"]?alias\.|GIT_CONFIG_(?:PARAMETERS|COUNT)=")
SHELL_SEPARATORS = ("&&", "||", ";", "|", "&", "(", ")", ";;", "|&")
DIRECTORY_COMMANDS = ("cd", "pushd")
ADD_ALL_ARGS = ("-A", "--all", ".", "*", ":/")
# A directory name the hook cannot resolve without a shell: expansions, globs and `~user`.
SHELL_EXPANSION_RE = re.compile(r"[$`*?\[{]|^~[^/]")


GIT_WORD_RE = re.compile(r"(?<![\w.-])(?:git|commit)(?![\w-])")
ANSI_C_ESCAPE_RE = re.compile(r"\$'[^']*\\")


def join_continuations(command):
    """Remove backslash-newline line continuations as bash does (not inside single quotes)."""
    out, i, n, single, double = [], 0, len(command), False, False
    while i < n:
        ch = command[i]
        if ch == "\\" and not single:
            if command.startswith("\n", i + 1):
                i += 2
                continue
            if command.startswith("\r\n", i + 1):
                i += 3
                continue
            out.append(command[i:i + 2])
            i += 2
            continue
        if ch == "'" and not double:
            single = not single
        elif ch == '"' and not single:
            double = not double
        out.append(ch)
        i += 1
    return "".join(out)


def _loose_git(command, sub):
    """True when `command` looks like `git ... <sub>` and nothing in between is another subcommand."""
    for m in GIT_LOOSE_RES[sub].finditer(command):
        words = re.findall(r"[\w-]+", m.group(1))
        if not any(w in OTHER_GIT_SUBCOMMANDS for w in words):
            return True
    return False


class GitCommand(object):
    """What a shell command does with git, as far as pii-guard needs to know."""

    def __init__(self, cwd):
        self.commit = False         # runs `git commit`
        self.commit_cwd = cwd       # directory of the first `git commit` (after cd, pushd and -C)
        self.commit_all = False     # `git commit -a` / `--all`
        self.add = False            # runs `git add`
        self.add_all = False        # `git add -A`, `--all`, `.`, `*` or `:/`
        self.redirected = False     # GIT_DIR=, GIT_INDEX_FILE=, --git-dir, --work-tree ...
        self.alias = False          # `git -c alias.x=...`: an alias may run commit under another name
        self.parse_failed = False   # it looks like git commit or add, but the tokens did not show it
        self.obfuscated = False     # git or its subcommand comes from a variable or ANSI-C quoting
        self.indirect = False       # a quoted `git commit` run by a program the hook does not parse
        self.unresolved_dir = None  # a cd, pushd or -C directory the hook cannot follow


def _change_dir(current, value, result):
    """Follow a cd, pushd or -C directory; remember when it cannot be resolved without a shell."""
    if value is None or value.startswith("-") or SHELL_EXPANSION_RE.search(value):
        result.unresolved_dir = result.unresolved_dir or (value or "(none)")
        return current
    return os.path.join(current, os.path.expanduser(value))


def _expansion_is_command(tokens, i):
    """For `$` + `(`: True only when the substitution's output is run with arguments
    (`$(which git) commit`). Its inner command is parsed on its own, so `echo "$(git commit)"` is
    not treated as hidden. Any other `$...` word in command position is an expansion."""
    if tokens[i] != "$" or i + 1 >= len(tokens) or tokens[i + 1] != "(":
        return True
    depth, k = 0, i + 1
    while k < len(tokens):
        depth += {"(": 1, ")": -1}.get(tokens[k], 0)
        if depth == 0:
            break
        k += 1
    return k + 1 < len(tokens) and tokens[k + 1] not in SHELL_SEPARATORS


def parse_git_command(command, cwd):
    """Find `git commit` and `git add` in the shell tokens, skipping global options and their values."""
    command = join_continuations(command or "")
    result = GitCommand(cwd)
    result.alias = bool(GIT_ALIAS_RE.search(command))
    hidden = []
    try:
        tokens, split_failed = _split(command, 0, hidden), False
        result.indirect = bool(hidden)
    except ValueError:
        tokens, split_failed = [], True
        result.redirected = bool(re.search(r"(?:^|[\s:])(?:GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|"
                                           r"GIT_OBJECT_DIRECTORY|GIT_COMMON_DIR)=|--git-dir|--work-tree",
                                           command))
    target, found_commit, moved = cwd, False, False
    cmds = _command_words(tokens)
    mentions_git = bool(GIT_WORD_RE.search(command))
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if GIT_REDIRECT_ENV_RE.search(tok):
            result.redirected = True
        # A variable, command substitution or ANSI-C string as the command word can hide git.
        if (cmds[i] == i and tok.lstrip("`").startswith("$") and _expansion_is_command(tokens, i)
                and (mentions_git or ANSI_C_ESCAPE_RE.search(command))):
            result.obfuscated = True
        if tok in DIRECTORY_COMMANDS:
            value = tokens[i + 1] if i + 1 < len(tokens) and tokens[i + 1] not in SHELL_SEPARATORS else None
            target, moved = _change_dir(target, value, result), True
            i += 2 if value is not None else 1
            continue
        if not _is_git(tok):
            i += 1
            continue
        j, local, local_moved = i + 1, target, moved
        while j < len(tokens) and tokens[j].startswith("-") and tokens[j] not in SHELL_SEPARATORS:
            opt = tokens[j]
            name = opt.split("=", 1)[0]
            if name in GIT_REDIRECT_OPTIONS:
                result.redirected = True
            if opt in GIT_VALUE_OPTIONS and j + 1 < len(tokens):
                if opt == "-C":
                    local, local_moved = _change_dir(local, tokens[j + 1], result), True
                elif opt in ("-c", "--config-env") and tokens[j + 1].lower().startswith("alias."):
                    result.alias = True
                elif opt in ("-c", "--config-env") and tokens[j + 1].startswith("$"):
                    result.obfuscated = True
                j += 2
            else:
                j += 1
        if j >= len(tokens):
            break
        sub, k, args = tokens[j].strip(), j + 1, []
        while k < len(tokens) and tokens[k] not in SHELL_SEPARATORS and not _is_git(tokens[k]):
            args.append(tokens[k])
            k += 1
        if sub.startswith("$") or "`" in sub or "$(" in sub:
            result.obfuscated = True  # the subcommand is a variable, substitution or ANSI-C string
        if sub == "commit":
            result.commit = True
            if not found_commit:
                result.commit_cwd, found_commit = local, True
                if local_moved and not os.path.isdir(local):
                    result.unresolved_dir = result.unresolved_dir or local
            if any(a == "--all" or re.match(r"^-[A-Za-z]*a[A-Za-z]*$", a) for a in args):
                result.commit_all = True
        elif sub == "add":
            result.add = True
            if any(a in ADD_ALL_ARGS for a in args):
                result.add_all = True
        elif sub not in OTHER_GIT_SUBCOMMANDS:
            # An unknown option or value before the subcommand: `git --frobnicate value commit`.
            for a in args:
                if a in ("commit", "add"):
                    result.parse_failed = True
                    break
                if a in OTHER_GIT_SUBCOMMANDS:
                    break
        i = k
    if split_failed:
        # Without tokens, anything that looks like git commit or add is scanned and the user is asked.
        result.parse_failed = bool(GIT_COMMIT_RE.search(command) or GIT_ADD_RE.search(command)
                                   or _loose_git(command, "commit") or _loose_git(command, "add"))
        result.obfuscated = result.obfuscated or bool(ANSI_C_ESCAPE_RE.search(command) and mentions_git)
    if result.alias or result.obfuscated or result.parse_failed or result.indirect:
        result.commit = True  # scan the commit and ask
    if result.parse_failed:
        result.commit_all = result.add_all = result.add = True
    return result


def is_git_commit(command):
    return parse_git_command(command, os.getcwd()).commit


class GitResult(object):
    """Output of one git call: `text` is None when git failed or ran out of time (`timed_out`)."""
    __slots__ = ("text", "truncated", "timed_out")

    def __init__(self, text=None, truncated=False, timed_out=False):
        self.text, self.truncated, self.timed_out = text, truncated, timed_out


def _git(args, cwd, limit, deadline):
    """Run git without a shell, for at most the time left until `deadline` (time.monotonic())."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return GitResult(timed_out=True)
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat",
                "GIT_EXTERNAL_DIFF": "", "LC_ALL": "C"})
    cmd = ["git", "-c", "core.fsmonitor=false", "-c", "diff.external=", "-c", "core.quotePath=false"] + args
    try:
        res = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, timeout=remaining)
    except subprocess.TimeoutExpired:
        return GitResult(timed_out=True)
    except (OSError, subprocess.SubprocessError):
        return GitResult()
    if res.returncode != 0:
        return GitResult()
    return GitResult(res.stdout[:limit].decode("utf-8", errors="replace"), len(res.stdout) > limit)


SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
POWERSHELL_NAMES = {"pwsh", "powershell"}
# Words after which the next word is again a command: shell keywords and command wrappers.
SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time"}
COMMAND_WRAPPERS = {"env", "sudo", "doas", "command", "builtin", "exec", "nohup", "nice", "xargs",
                    "busybox"}
# Programs whose `-c` argument is a command line, and the `find` options that start a command.
C_FLAG_RUNNERS = SHELL_NAMES | {"su"}
FIND_EXEC_OPTIONS = ("-exec", "-execdir", "-ok", "-okdir")
# Programs that only print or search text: a quoted argument of theirs that mentions `git commit` is
# not a command, as long as nothing in the command line runs anything (EXECUTING_PROGRAMS). Any
# other program's quoted argument that looks like one (python -c, node -e, ssh host "...", and awk
# or sed, which can run commands) is not parsed, so the commit is scanned and the user is asked.
NON_EXECUTING_PROGRAMS = {"grep", "rg", "ag", "ack", "echo", "printf", "jq", "cat", "gh", "git"}
# Git subcommands that only read data; for `git`, the exemption above applies only to these (and to
# `commit`, whose own message is not run). `config` counts only with a read option.
DATA_ONLY_GIT_SUBCOMMANDS = {
    "commit", "log", "show", "grep", "diff", "status", "blame", "shortlog", "describe", "rev-parse",
    "rev-list", "help", "ls-files", "ls-tree", "cat-file", "reflog", "whatchanged", "name-rev",
    "for-each-ref", "show-ref", "count-objects", "var", "version",
}
GIT_CONFIG_READ_OPTIONS = ("--get", "--get-all", "--get-regexp", "--list", "-l", "get", "list")
# Git subcommands that run a command line given as an argument.
GIT_EXEC_OPTIONS = ("-x", "--exec", "--extcmd", "--tree-filter", "--index-filter", "--msg-filter",
                    "--env-filter", "--commit-filter", "--parent-filter", "--tag-name-filter")
GIT_EXEC_SUBCOMMANDS = ("rebase", "difftool", "mergetool", "filter-branch")
# Programs that run commands, scripts or code. When any of them (or a command word that is a path)
# appears anywhere in a command line, text written or piped by a text tool may be run, so the
# text-tool exemption does not apply to that command line.
EXECUTING_PROGRAMS = SHELL_NAMES | POWERSHELL_NAMES | {
    "source", ".", "exec", "eval", "xargs", "busybox", "su", "parallel", "watch", "script", "tmux",
    "screen", "flock", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "luajit",
    "tclsh", "rscript", "osascript", "ssh",
}
INTERPRETER_RE = re.compile(r"^(?:python|pypy)[0-9.]*$")
GIT_RUNNING_SUBCOMMANDS = {"rebase", "filter-branch", "difftool", "mergetool", "submodule", "bisect"}
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _program(tok):
    name = os.path.basename(tok.strip("`").replace("\\", "/")).lower()
    return name[:-4] if name.endswith(".exe") else name


def _git_subcommand(toks, git_index):
    """Index of the subcommand after `git` and its global options, or None."""
    j = git_index + 1
    while j < len(toks) and toks[j].startswith("-") and toks[j] not in SHELL_SEPARATORS:
        j += 2 if toks[j] in GIT_VALUE_OPTIONS else 1
    return j if j < len(toks) and toks[j] not in SHELL_SEPARATORS else None


def _command_words(toks):
    """For each token, the index of the command word of its simple command, or None.

    The command word is the first word of a segment after variable assignments, shell keywords and
    wrappers such as `env` or `sudo` (and their options); a backtick also starts a command, and so do
    `find -exec`, `git submodule foreach` and `git bisect run`."""
    out, cmd, pending = [], None, True
    for n, t in enumerate(toks):
        if t in SHELL_SEPARATORS:
            out.append(None)
            cmd, pending = None, True
            continue
        if t.startswith("`"):
            pending = True
        if n > 0 and cmd is not None:
            program, prev = _program(toks[cmd]), toks[n - 1]
            if program == "find" and prev in FIND_EXEC_OPTIONS:
                pending = True
            elif program == "git" and (prev == "foreach" or (prev == "run" and n > 1 and toks[n - 2] == "bisect")):
                pending = True
        if pending:
            bare = t.lstrip("`")
            wrapped = cmd is not None and _program(toks[cmd]) in COMMAND_WRAPPERS
            if bare in SHELL_KEYWORDS or ASSIGNMENT_RE.match(bare) or (wrapped and bare.startswith("-")):
                out.append(None)
                continue
            cmd = n
            pending = _program(bare) in COMMAND_WRAPPERS
        out.append(cmd)
    return out


def _has_execution(toks, cmds):
    """True when the command line runs something that could execute text a text tool wrote:
    a shell, an interpreter, source/exec/eval/xargs, a command word that is a path, `find -exec`,
    `env -S`, or a git subcommand that runs commands."""
    for n, t in enumerate(toks):
        cmd = cmds[n]
        if cmd is None:
            continue
        program = _program(toks[cmd])
        if cmd == n:
            if program in EXECUTING_PROGRAMS or INTERPRETER_RE.match(program) or "/" in t.strip("`"):
                return True
            continue
        if program == "find" and t in FIND_EXEC_OPTIONS:
            return True
        if program == "env" and (t in ("-S", "--split-string") or t.startswith("--split-string=")):
            return True
        if program == "git" and t in GIT_RUNNING_SUBCOMMANDS and _git_subcommand(toks, cmd) == n:
            return True
    return False


def _runs_as_command(toks, cmds, n):
    """True when token n is itself a command line: `sh -c '...'`, `eval '...'`, `pwsh -Command '...'`,
    `git rebase -x '...'`, `git submodule foreach '...'` or a command substitution (`$(...)`,
    backticks). Other quoted arguments, such as the pattern of `grep "git commit"`, are not split
    again unless the command line also runs something (see _has_execution)."""
    t = toks[n]
    if "$(" in t or "`" in t:
        return True
    cmd = cmds[n]
    if cmd is not None and cmd == n and n > 0 and toks[n - 1] in ("foreach", "run"):
        return True  # `git submodule foreach '...'`, `git bisect run '...'`
    if cmd is None or cmd >= n:
        return False
    program, prev = _program(toks[cmd]), toks[n - 1]
    if program == "eval":
        return True
    if program in C_FLAG_RUNNERS and re.match(r"^-[A-Za-z]*c[A-Za-z]*$", prev):
        return True
    if program in SHELL_NAMES and prev == "<<<":
        return True
    if program == "git" and prev in GIT_EXEC_OPTIONS:
        sub = _git_subcommand(toks, cmd)
        return sub is not None and toks[sub] in GIT_EXEC_SUBCOMMANDS
    return program in POWERSHELL_NAMES and prev.lower() in ("-c", "-command", "-commandwithargs")


def _git_exec_value(toks, cmds, n):
    """The command line in `git rebase --exec=...` or `git filter-branch --tree-filter=...`, or None."""
    t, cmd = toks[n], cmds[n]
    if cmd is None or cmd >= n or _program(toks[cmd]) != "git" or "=" not in t:
        return None
    name, value = t.split("=", 1)
    sub = _git_subcommand(toks, cmd)
    if name in GIT_EXEC_OPTIONS and sub is not None and toks[sub] in GIT_EXEC_SUBCOMMANDS:
        return value
    return None


def _env_split_string(toks, n):
    """`env -S 'git commit -m x'` / `env --split-string=...`: env runs the string as a command line."""
    if n == 0 or toks[n - 1] not in ("-S", "--split-string"):
        return False
    k = n - 1
    while k > 0 and toks[k - 1] not in SHELL_SEPARATORS:
        k -= 1
        if _program(toks[k]) == "env":
            return True
    return False


REDIRECTIONS = (">", ">>", ">|", "&>", "&>>", "1>")
TEXT_TOOLS = NON_EXECUTING_PROGRAMS | {"tee"}


SCRIPT_EXTENSIONS = (".sh", ".bash", ".zsh", ".ksh", ".ps1", ".command")


def _looks_like_script(path):
    """A file name ending in a script extension, or with no extension at all (devices excluded)."""
    if path.startswith("/dev/") or path.startswith("&"):
        return False
    name = os.path.basename(path.replace("\\", "/")).lower()
    if not name:
        return False
    return name.endswith(SCRIPT_EXTENSIONS) or "." not in name.lstrip(".")


def _writes_script_file(toks, cmds):
    """True when a text tool's output goes to a file that looks like a script (`> s.sh`,
    `>> run`, `| tee deploy.sh`), which may be run by a later tool call."""
    for n, t in enumerate(toks):
        if t in REDIRECTIONS and n + 1 < len(toks) and _looks_like_script(toks[n + 1]):
            if n > 0 and toks[n - 1] in ("}", ")"):
                return True  # the output of a group or subshell: `{ echo ...; } > s.sh`
            k = n - 1
            while k >= 0 and cmds[k] is None and toks[k] not in SHELL_SEPARATORS:
                k -= 1
            if k >= 0 and cmds[k] is not None and _program(toks[cmds[k]]) in NON_EXECUTING_PROGRAMS:
                return True
        elif cmds[n] is not None and cmds[n] < n and _program(toks[cmds[n]]) == "tee":
            if not t.startswith("-") and t not in SHELL_SEPARATORS and _looks_like_script(t):
                return True
    return False


def _exempt_text_argument(toks, cmds, n, script_write=False):
    """True when token n is an argument of a text-only program whose output is not piped onward
    to anything but text-only programs, so a `git commit` in it is only text."""
    cmd = cmds[n]
    if cmd is None or cmd >= n:
        return False
    program = _program(toks[cmd])
    if program not in TEXT_TOOLS or script_write:
        return False
    if program == "git":
        sub = _git_subcommand(toks, cmd)
        if sub is None or sub >= n:
            return False
        if toks[sub] == "config":
            return any(a in GIT_CONFIG_READ_OPTIONS for a in toks[sub + 1:n + 1])
        return toks[sub] in DATA_ONLY_GIT_SUBCOMMANDS
    return True


def _split(command, depth=0, hidden=None):
    """Shell-like tokens; an argument that is itself a command line (bash -c '...') is split again.

    A quoted argument that looks like `git ... commit` or `add` but is run by a program the hook does
    not parse (python -c, ssh ...) is appended to `hidden`, if given.
    Raises ValueError when the command cannot be tokenised (for example an unclosed quote)."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    toks = list(lex)
    cmds = _command_words(toks)
    execution = _has_execution(toks, cmds)
    script_write = _writes_script_file(toks, cmds)
    out = []
    for n, t in enumerate(toks):
        if depth < 3 and re.search(r"\s", t):
            inner = _git_exec_value(toks, cmds, n)
            if inner is None and (_runs_as_command(toks, cmds, n) or _env_split_string(toks, n)
                                  or (execution and cmds[n] is not None and cmds[n] < n
                                      and _program(toks[cmds[n]]) in TEXT_TOOLS)):
                inner = t
            if inner is not None:
                out.append(";")
                out.extend(_split(inner, depth + 1, hidden))
                out.append(";")
                continue
        if (hidden is not None and re.search(r"\s", t) and (_loose_git(t, "commit") or _loose_git(t, "add"))
                and not _exempt_text_argument(toks, cmds, n, script_write)):
            hidden.append(t)
        out.append(t)
    return out


def _tokens(command):
    try:
        return _split(join_continuations(command))
    except ValueError:
        return []


def _is_git(tok):
    return os.path.basename(tok.strip("`").replace("\\", "/")) in ("git", "git.exe")


def _commit_cwd(command, cwd):
    """Best effort: follow `cd DIR &&` and `git -C DIR` before `commit`."""
    return parse_git_command(command, cwd).commit_cwd


def _message_files(command, cwd):
    tokens = _tokens(command)
    files = []
    for i, tok in enumerate(tokens):
        if tok in ("-F", "--file") and i + 1 < len(tokens):
            files.append(tokens[i + 1])
        elif tok.startswith("--file="):
            files.append(tok[len("--file="):])
        elif tok.startswith("-F") and len(tok) > 2:
            files.append(tok[2:])
    return [os.path.join(cwd, os.path.expanduser(f)) for f in files if f != "-"]


def parse_diff(diff):
    """Yield (path, first_new_line, text) for each run of added lines in a unified diff."""
    path, line, run, run_start = None, 0, [], 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            if run:
                yield path, run_start, "\n".join(run)
                run = []
            p = raw[4:].strip()
            if p.startswith('"') and p.endswith('"'):
                p = p[1:-1]
            path = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
        elif raw.startswith("@@"):
            if run:
                yield path, run_start, "\n".join(run)
                run = []
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            line = int(m.group(1)) if m else 0
        elif raw.startswith("+") and path is not None:
            if not run:
                run_start = line
            run.append(raw[1:])
            line += 1
        elif raw.startswith(" "):
            if run:
                yield path, run_start, "\n".join(run)
                run = []
            line += 1
        elif raw.startswith("diff --git"):
            if run:
                yield path, run_start, "\n".join(run)
                run = []
            path = None
    if run:
        yield path, run_start, "\n".join(run)


BINARY_DIFF_RE = re.compile(r"^Binary files .*? and (.+) differ$", re.M)


def binary_diff_paths(diff):
    """Paths of added or changed binary files in a unified diff (git prints no lines for them)."""
    paths = []
    for m in BINARY_DIFF_RE.finditer(diff):
        p = m.group(1).strip()
        if p.startswith('"') and p.endswith('"'):
            p = p[1:-1]
        if p != "/dev/null":
            paths.append(p[2:] if p.startswith("b/") else p)
    return paths


def _staged_blob(root, path, limit, deadline):
    """Return (text, None) for the staged content of `path`, or (None, reason) if it was not read."""
    if "\n" in path:
        return None, "the path could not be passed to git"
    size = _git(["cat-file", "-s", ":" + path], root, 64, deadline)
    if size.text is None:
        return None, TIME_LIMIT_REASON if size.timed_out else "git could not read the staged file"
    try:
        if int(size.text.strip()) > limit:
            return None, _too_large(limit)
    except ValueError:
        return None, "git could not read the staged file"
    blob = _git(["cat-file", "blob", ":" + path], root, limit, deadline)
    if blob.text is None:
        return None, TIME_LIMIT_REASON if blob.timed_out else "git could not read the staged file"
    return blob.text, None


def _binary_in_diff(label, path, root, limit, deadline):
    """A file git shows without a text diff: binary by its rules or by .gitattributes (`-diff`).

    The content that will be committed is read (the staged blob, or the working-tree file for the
    unstaged diff). Real binary content is skipped with a note; text is scanned as a whole; anything
    that could not be read counts as not scanned."""
    cut = None
    if label == "staged diff":
        where = "staged"
        text, reason = _staged_blob(root, path, limit, deadline)
        if text is not None and "\0" in text[:8192]:
            text, reason = None, "binary"
    else:
        where = "working tree"
        text, info = _read_text(os.path.join(root, path), limit)
        if text is None:
            reason = info if info == "binary" else "file is %s and was not read" % info
        else:
            cut = _too_large(limit) if info else None
    if text is None and reason == "binary":
        return Source(path, "", 1, path, binary_skipped=True)
    return Source("%s (%s, no text diff)" % (path, where), text or "", 1, path,
                  unscanned=reason if text is None else cut)


def commit_sources(command, cwd, config, notes, deadline, parsed=None):
    limit = config["max_scan_bytes"]
    cmd_text, cut = _limited(command, limit)
    sources = [Source("git commit command (message)", cmd_text, 1, None,
                      skip_trailers=config["allow_trailers"], unscanned=_too_large(limit) if cut else None)]
    parsed = parsed or parse_git_command(command, cwd or os.getcwd())
    if parsed.parse_failed:
        sources.append(Source("git command", "", 1, None,
                              unscanned="the command could not be parsed; it was scanned as a commit "
                              "in the current directory"))
    if parsed.obfuscated:
        sources.append(Source("git command", "", 1, None,
                              unscanned="git or its subcommand comes from a variable, a command "
                              "substitution or $'...' quoting, which the hook does not expand"))
    if parsed.indirect:
        sources.append(Source("git command", "", 1, None,
                              unscanned="a quoted argument looks like a git commit run by another "
                              "program (for example python -c or ssh), which the hook does not parse"))
    if parsed.alias:
        sources.append(Source("git command", "", 1, None,
                              unscanned="it defines a git alias, which the hook does not follow"))
    if parsed.unresolved_dir:
        sources.append(Source("git command", "", 1, None,
                              unscanned="the commit directory %s could not be resolved (missing, or "
                              "a shell expansion), so the repository scanned may not be the one "
                              "committed to" % parsed.unresolved_dir))
    if parsed.redirected:
        sources.append(Source("git command", "", 1, None,
                              unscanned="it points git at another repository, work tree or index "
                              "(GIT_DIR, GIT_INDEX_FILE, --git-dir, --work-tree ...), which the hook "
                              "does not follow"))
    commit_cwd = parsed.commit_cwd if os.path.isdir(parsed.commit_cwd) else (cwd or os.getcwd())
    for f in _message_files(command, commit_cwd):
        if not os.path.lexists(f):
            continue  # git itself fails on a missing message file, nothing is committed
        text, info = _read_text(f, limit)
        if text is None:
            sources.append(Source("commit message file %s" % f, "", 1, None,
                                  unscanned="message file is %s and was not read" % info))
        else:
            sources.append(Source("commit message file %s" % f, text, 1, None,
                                  skip_trailers=config["allow_trailers"],
                                  unscanned=_too_large(limit) if info else None))
    found = _git(["rev-parse", "--show-toplevel"], commit_cwd, 4096, deadline)
    if found.timed_out:
        sources.append(Source("repository content", "", 1, None,
                              unscanned="git did not answer in time; " + TIME_LIMIT_REASON))
        return sources, None
    if found.text is None:
        notes.append("not a git repository or git unavailable; only the commit message was scanned")
        return sources, None
    root = found.text.strip()
    diff_args = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=0", "--diff-filter=ACMRT"]
    diffs = [("staged diff", _git(diff_args + ["--cached"], root, limit, deadline))]
    if parsed.add or parsed.commit_all:
        # tracked changes not yet staged
        diffs.append(("unstaged diff", _git(diff_args, root, limit, deadline)))
    if parsed.add_all:
        listing = _git(["ls-files", "--others", "--exclude-standard", "-z"], root, limit, deadline)
        if listing.text is None:
            reason = TIME_LIMIT_REASON if listing.timed_out else "git could not list them"
            sources.append(Source("untracked files", "", 1, None, unscanned=reason))
        elif listing.truncated:
            sources.append(Source("untracked file list", "", 1, None, unscanned=_too_large(limit)))
        for rel in [p for p in (listing.text or "").split("\0") if p]:
            path = os.path.join(root, rel)
            label = rel + " (untracked, staged by git add)"
            if time.monotonic() > deadline:
                sources.append(Source(label, "", 1, rel, unscanned=TIME_LIMIT_REASON))
                continue
            text, info = _read_text(path, limit)
            if text is not None:
                sources.append(Source(label, text, 1, rel, unscanned=_too_large(limit) if info else None))
            elif info == "binary":
                sources.append(Source(rel, "", 1, rel, binary_skipped=True))
            elif not os.path.isdir(path):  # a nested repository is listed as a directory
                sources.append(Source(label, "", 1, rel, unscanned="file is %s and was not read" % info))
    for label, result in diffs:
        if result.text is None:
            reason = TIME_LIMIT_REASON if result.timed_out else "git could not produce it"
            sources.append(Source(label, "", 1, None, unscanned=reason))
            continue
        if result.truncated:
            sources.append(Source(label, "", 1, None, unscanned=_too_large(limit)))
        for path, first, text in parse_diff(result.text):
            sources.append(Source(path, text, first, path))
        for path in binary_diff_paths(result.text):
            sources.append(_binary_in_diff(label, path, root, limit, deadline))
    return sources, root


# --------------------------------------------------------------------------------------------------
# Hook entry point
# --------------------------------------------------------------------------------------------------

FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
SHELL_TOOLS = ("Bash", "PowerShell")
MAX_FINDINGS = 50
CHUNK_CHARS = 1000000
DONT_BYPASS = "Do not add exceptions or allow markers yourself; ask the user."


class InputError(ValueError):
    pass


def _shell_guard_reason(command, config):
    low = command.lower()
    if REPO_CONFIG_NAME in low or ".config/pii-guard" in low or os.path.dirname(user_config_path()).lower() in low:
        return "the command touches pii-guard's configuration"
    if count_markers(command, config):
        return "the command contains a pii-guard allow marker"
    return None


def evaluate(payload, deadline=None):
    """Return the decision JSON, or None to stay silent."""
    if os.environ.get("PII_GUARD_DISABLE") == "1":
        return None
    tool = payload.get("tool_name")
    tin = payload.get("tool_input")
    if not isinstance(tool, str):
        raise InputError("tool_name must be a string")
    if tool not in FILE_TOOLS + SHELL_TOOLS:
        return None
    if not isinstance(tin, dict):
        raise InputError("tool_input must be a JSON object")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else os.getcwd()
    command = tin.get("command") if isinstance(tin.get("command"), str) else ""
    deadline = deadline or (time.monotonic() + TIME_BUDGET_SECONDS)
    notes, guard = [], []
    if tool in FILE_TOOLS:
        path = tin.get("file_path") or tin.get("notebook_path") or ""
        path = path if isinstance(path, str) else ""
        repo_root = find_repo_root(os.path.dirname(path) if path else cwd) or find_repo_root(cwd)
        config = load_config(repo_root, notes)
        sources = file_sources(tool, tin, repo_root, config)
        action = "%s to %s" % (tool, relpath(path, repo_root) if path else "a file")
        if touches_guard_config(path):
            guard.append("this change edits pii-guard's configuration")
        if marker_added(tool, tin, config):
            guard.append("this change adds a pii-guard allow marker")
    else:
        parsed = parse_git_command(command, cwd)
        repo_root = find_repo_root(parsed.commit_cwd) or find_repo_root(cwd)
        config = load_config(repo_root, notes)
        reason = _shell_guard_reason(command, config)
        if reason:
            guard.append(reason)
        if parsed.commit:
            sources, git_root = commit_sources(command, cwd, config, notes, deadline, parsed)
            repo_root = git_root or repo_root
        else:
            sources = []
        action = "git commit" if sources else "%s command" % tool

    phrases = resolve_phrases(config, repo_root, notes) if config["detectors"].get("phrases") else []
    report, unscanned, binaries, stopped = [], [], [], False
    for src in sources:
        if src.rel_path and path_ignored(src.rel_path, config):
            continue
        if src.binary_skipped:
            if src.label not in binaries:
                binaries.append(src.label)
            continue
        if src.unscanned:
            unscanned.append("%s: %s" % (src.label, src.unscanned))
        skip = (lambda prefix: bool(TRAILER_RE.search(prefix))) if src.skip_trailers else None
        for piece, offset in iter_chunks(src.text, CHUNK_CHARS):
            if len(report) >= MAX_FINDINGS:
                stopped = True
                break
            if time.monotonic() > deadline:
                unscanned.append("%s: scan time limit reached" % src.label)
                break
            for f in scan_text(piece, config, phrases, skip_line=skip, limit=MAX_FINDINGS - len(report)):
                if normalize(f.value) in src.known:
                    continue
                report.append((src.label, src.first_line + offset + f.line - 1, f))
        if stopped:
            break
    if len(report) >= MAX_FINDINGS:
        stopped = True
    if binaries:
        notes.append(binary_note(binaries))
    return build_decision(action, report, unscanned, guard, config["mode"], notes, stopped)


def binary_note(paths):
    shown = ", ".join(paths[:10])
    more = " and %d more" % (len(paths) - 10) if len(paths) > 10 else ""
    return "binary files skipped, not scanned for personal data: %s%s" % (shown, more)


def build_decision(action, report, unscanned, guard, mode, notes, stopped=False):
    if not (report or unscanned or guard):
        return {"systemMessage": "pii-guard: " + "; ".join(notes)} if notes else None
    lines = []
    if report:
        lines.append("pii-guard: possible personal data in %s." % action)
        for label, line, f in report[:20]:
            lines.append('  - %s, line %d: %s "%s"' % (label, line, f.kind, mask(f.value, f.kind)))
        if stopped:
            lines.append("  ... %d or more findings; the scan stopped at the first %d" % (MAX_FINDINGS, MAX_FINDINGS))
        elif len(report) > 20:
            lines.append("  ... and %d more" % (len(report) - 20))
        lines.append("Replace it with synthetic data (for example user@example.com) or remove it.")
    if unscanned:
        lines.append("pii-guard: part of %s could not be scanned:" % action)
        lines.extend("  - " + u for u in unscanned[:10])
    if guard:
        lines.append("pii-guard: %s; the user has to confirm it." % "; ".join(guard))
    lines.append(DONT_BYPASS)
    if notes:
        lines.append("Notes: " + "; ".join(notes))
    message = "\n".join(lines)
    user_message = message + "\n(Exceptions are set by you, not by Claude: see the pii-guard README, Configuration.)"
    if report and mode == "block":
        decision = "deny"
    elif guard or mode in ("block", "ask"):
        decision = "ask"
    else:
        decision = None  # warn
    if decision is None:
        return {"systemMessage": user_message,
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "additionalContext": message + "\n(mode: warn, the action was allowed)"}}
    return {"systemMessage": user_message,
            "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": message}}


def run_hook(stdin_text):
    try:
        payload = json.loads(stdin_text or "")
        if not isinstance(payload, dict):
            raise InputError("expected a JSON object")
        result = evaluate(payload)
    except (ValueError, InputError) as exc:
        sys.stderr.write("pii-guard: invalid hook input: %s\n" % exc)
        return 1, ""
    return 0, (json.dumps(result, ensure_ascii=False) if result else "")


def run_scan(paths):
    """CLI: scan files with the same rules.

    Exit 1 when anything is found or a file could not be scanned (too large, unreadable, not a
    regular file). A binary file is reported as skipped and does not change the exit code."""
    notes, found = [], 0
    for p in paths:
        repo_root = find_repo_root(p)
        config = load_config(repo_root, notes)
        rel = relpath(os.path.abspath(p), repo_root)
        if path_ignored(rel, config):
            continue
        text, info = _read_text(p, config["max_scan_bytes"])
        if text is None:
            if info == "binary":
                print("%s: binary file skipped, not scanned" % rel)
            else:
                found += 1
                print("%s: not scanned (%s)" % (rel, info))
            continue
        if info:
            found += 1
            print("%s: %s" % (rel, _too_large(config["max_scan_bytes"])))
        phrases = resolve_phrases(config, repo_root, notes)
        for piece, offset in iter_chunks(text, CHUNK_CHARS):
            for f in scan_text(piece, config, phrases):
                found += 1
                print('%s:%d: %s "%s"' % (rel, offset + f.line, f.kind, mask(f.value, f.kind)))
    for n in notes:
        sys.stderr.write("pii-guard: %s\n" % n)
    return 1 if found else 0


def main(argv):
    if len(argv) > 1 and argv[1] == "--version":
        print("pii-guard " + VERSION)
        return 0
    if len(argv) > 1 and argv[1] == "scan":
        return run_scan(argv[2:])
    code, out = run_hook(sys.stdin.read())
    if out:
        sys.stdout.write(out + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
