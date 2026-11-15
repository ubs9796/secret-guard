#!/usr/bin/env python3
"""secret-guard: a fast, zero-dependency pre-commit secret scanner.

Stage 1 scans staged Git diff lines locally with regexes and entropy checks.
Stage 2, when NVIDIA_API_KEY is set, sends a sanitized diff to the NVIDIA NIM
API for a second-pass review and a Conventional Commit message suggestion.

The local stage never sends detected secrets to the network. The NIM stage is
best-effort and fails open so a timeout or outage cannot block a commit.

Only the Python standard library is used.
"""

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

VERSION = "1.0.0"
NIM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
DEFAULT_TIMEOUT = 5.0
MAX_DIFF_CHARS = 16000
HOOK_MARKER = "# managed by secret-guard"

AWS_KEY_ID_RE = re.compile(
    r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA)[0-9A-Z]{16}\b"
)
AWS_SECRET_RE = re.compile(
    r"""aws[_\- ]?secret[_\- ]?access[_\- ]?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})""",
    re.IGNORECASE,
)
NVIDIA_KEY_RE = re.compile(r"\bnvapi-[A-Za-z0-9_\-]{20,}")
STRIPE_KEY_RE = re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_ENV_KEY_PATTERN = (
    r"[A-Za-z0-9_.\-]*"
    r"(?:SECRET(?:[_\-]?KEY)?|PASSWORD|PASSWD|TOKEN|API[_\-]?KEY|"
    r"PRIVATE[_\-]?KEY|ACCESS[_\-]?KEY|CLIENT[_\-]?SECRET|CREDENTIALS?)"
    r"[A-Za-z0-9_.]*"
)
ENV_SECRET_RE = re.compile(
    r"^\s*(?:export\s+)?("
    + _ENV_KEY_PATTERN
    + r")\s*[:=]\s*([\"']?)([^\s\"',}]{8,})\2",
    re.IGNORECASE,
)
ENV_QUOTED_SECRET_RE = re.compile(
    r"^\s*(?:export\s+)?[\"']("
    + _ENV_KEY_PATTERN
    + r")[\"']\s*[:=]\s*([\"']?)([^\s\"',}]{8,})\2",
    re.IGNORECASE,
)
# Used only for outbound sanitization so even short values never reach the API.
ENV_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?("
    + _ENV_KEY_PATTERN
    + r")\s*[:=]\s*([\"']?)([^\s\"',}]+)\2",
    re.IGNORECASE,
)
ENV_QUOTED_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?[\"']("
    + _ENV_KEY_PATTERN
    + r")[\"']\s*[:=]\s*([\"']?)([^\s\"',}]+)\2",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=\-_]{24,}")

# (rule name, compiled regex, group holding the secret value)
RULES = (
    ("aws_access_key", AWS_KEY_ID_RE, 0),
    ("aws_secret_key", AWS_SECRET_RE, 1),
    ("nvidia_api_key", NVIDIA_KEY_RE, 0),
    ("stripe_secret_key", STRIPE_KEY_RE, 0),
    ("private_key", PRIVATE_KEY_RE, 0),
    ("env_secret", ENV_SECRET_RE, 3),
    ("env_secret", ENV_QUOTED_SECRET_RE, 3),
)

PLACEHOLDER_RE = re.compile(
    r"""(?i)^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]+>|x{3,}|\*{3,}|\.{3,}|"""
    r"""changeme|change[_-]?me|your[_-].*|example|placeholder|dummy|sample|"""
    r"""redacted|secret|password|token|api[_-]?key|none|null|true|false|"""
    r"""test(?:ing)?|-+)$"""
)

ENTROPY_SKIP_GLOBS = (
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.pem",
    "*.crt",
    "*.cer",
    "*.der",
    "*.pub",
    "*.asc",
)

SENSITIVE_FILE_NAMES = {
    ".env",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

REVIEW_SYSTEM_PROMPT = (
    "You are a pre-commit security reviewer and commit message writer. "
    "The diff has already been sanitized; do not ask for secrets. "
    "Look for subtle security issues such as command injection, SQL injection, "
    "unsafe eval/exec, weak crypto, auth bypass, insecure deserialization, "
    "path traversal, secrets being logged, and leftover debug code. Ignore style. "
    "Reply in exactly this format, with no code fences and no preamble:\n"
    "VERDICT: OK or BLOCK\n"
    "REASON: one short sentence\n"
    "MESSAGE: a Conventional Commit message (type(scope): summary) under 72 chars"
)

DRAFT_SYSTEM_PROMPT = (
    "Write a Conventional Commit message for the staged diff. Use one of: feat, "
    "fix, docs, style, refactor, perf, test, build, ci, chore, revert. The first "
    "line must be type(scope): imperative summary, max 72 characters. Add a blank "
    "line and up to 3 short bullet points only if useful. Return only the commit "
    "message, no code fences, no preamble. Never include secrets."
)


class SecretGuardError(Exception):
    """A user-facing error that should exit with status 2."""


class Finding:
    """A potential secret. The raw value is intentionally absent from repr()."""

    __slots__ = ("rule", "file", "line", "value", "fingerprint")

    def __init__(self, rule, file, line, value):
        self.rule = rule
        self.file = file
        self.line = line
        self.value = value
        self.fingerprint = fingerprint(value)

    def __repr__(self):
        return "Finding(rule=%r, file=%r, line=%r, fingerprint=%r)" % (
            self.rule,
            self.file,
            self.line,
            self.fingerprint,
        )


class IgnoreRules:
    """Parsed .secretguardignore rules."""

    __slots__ = ("paths", "rules", "fingerprints", "matches")

    def __init__(self):
        self.paths = []
        self.rules = set()
        self.fingerprints = set()
        self.matches = []

    def ignores_file(self, path):
        normalized = path.replace(os.sep, "/")
        for pattern in self.paths:
            normalized_pattern = pattern.replace(os.sep, "/")
            if fnmatch.fnmatch(normalized, normalized_pattern):
                return True
            if "/" not in normalized_pattern and fnmatch.fnmatch(
                os.path.basename(normalized), normalized_pattern
            ):
                return True
        return False

    def ignores(self, finding):
        if finding.rule in self.rules:
            return True
        for prefix in self.fingerprints:
            if finding.fingerprint.startswith(prefix):
                return True
        return any(value in finding.value for value in self.matches)


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder_or_reference(value):
    candidate = value.strip().strip("\"'")
    if not candidate:
        return True
    if PLACEHOLDER_RE.match(candidate):
        return True
    if candidate.startswith("$"):
        return True
    return any(char in candidate for char in "(){}[]")


def is_high_entropy(token):
    if len(token) < 24 or token.isdigit():
        return False
    if is_placeholder_or_reference(token):
        return False
    classes = 0
    if any(char.islower() for char in token):
        classes += 1
    if any(char.isupper() for char in token):
        classes += 1
    if any(char.isdigit() for char in token):
        classes += 1
    if classes < 2:
        return False
    return shannon_entropy(token) >= 4.5


def is_entropy_skip(path):
    normalized = path.replace(os.sep, "/")
    base = os.path.basename(normalized)
    return any(
        fnmatch.fnmatch(base, pattern) or fnmatch.fnmatch(normalized, pattern)
        for pattern in ENTROPY_SKIP_GLOBS
    )


def is_sensitive_path(path):
    normalized = path.replace(os.sep, "/")
    base = os.path.basename(normalized).lower()
    if base in SENSITIVE_FILE_NAMES:
        return True
    if base.startswith(".env.") or base.endswith(".env"):
        return True
    return base.endswith((".pem", ".key", ".p12", ".pfx"))


def _unquote_git_path(path):
    path = path.strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        inner = path[1:-1]
        try:
            decoded = bytes(inner, "utf-8").decode("unicode_escape")
            try:
                decoded = decoded.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                pass
            return decoded
        except (UnicodeDecodeError, ValueError):
            return inner
    return path


def iter_added_lines(diff_text):
    """Yield (file, new_line_number, content) for added diff lines."""
    current_file = None
    new_line = 0
    in_hunk = False

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            in_hunk = False
            continue
        if not in_hunk and raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current_file = None
            else:
                path = _unquote_git_path(path)
                if path.startswith("b/"):
                    path = path[2:]
                current_file = path
            continue
        if not in_hunk and raw.startswith("--- "):
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            if match:
                new_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk or current_file is None:
            continue
        if raw.startswith("+"):
            yield current_file, new_line, raw[1:]
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1


def _spans_overlap(first, second):
    return first[0] < second[1] and second[0] < first[1]


def scan_line(content, file, line_no):
    findings = []
    spans = []
    for rule, regex, group in RULES:
        for match in regex.finditer(content):
            value = match.group(group)
            if not value:
                continue
            if rule == "env_secret" and is_placeholder_or_reference(value):
                continue
            spans.append(match.span(group))
            findings.append(Finding(rule, file, line_no, value))

    if not is_entropy_skip(file):
        for match in TOKEN_RE.finditer(content):
            if any(_spans_overlap(match.span(), span) for span in spans):
                continue
            token = match.group(0)
            if is_high_entropy(token):
                findings.append(Finding("high_entropy", file, line_no, token))
    return findings


def scan_diff(diff_text, ignore=None):
    ignore = ignore or IgnoreRules()
    findings = []
    seen = set()
    private_key_files = set()

    for file, line_no, content in iter_added_lines(diff_text):
        if os.path.basename(file) == ".secretguardignore" or ignore.ignores_file(file):
            continue
        for finding in scan_line(content, file, line_no):
            # One finding per value per line. Specific rules are checked before
            # the generic env rule, so the more precise rule wins.
            key = (finding.file, finding.line, finding.fingerprint)
            if key in seen or ignore.ignores(finding):
                continue
            seen.add(key)
            findings.append(finding)
            if finding.rule == "private_key":
                private_key_files.add(finding.file)

    if private_key_files:
        findings = [
            finding
            for finding in findings
            if not (finding.rule == "high_entropy" and finding.file in private_key_files)
        ]

    findings.sort(key=lambda item: (item.file, item.line, item.rule))
    return findings


def load_ignore(repo_root="."):
    rules = IgnoreRules()
    path = os.path.join(repo_root, ".secretguardignore")
    if not os.path.isfile(path):
        return rules
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return rules

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("path:"):
            pattern = line[5:].strip()
            if pattern:
                rules.paths.append(pattern)
        elif line.startswith("rule:"):
            name = line[5:].strip()
            if name:
                rules.rules.add(name)
        elif line.startswith("fingerprint:"):
            prefix = line[12:].strip().lower()
            if len(prefix) >= 8:
                rules.fingerprints.add(prefix)
        elif line.startswith("match:"):
            value = line[6:]
            if value:
                rules.matches.append(value)
        else:
            rules.paths.append(line)
    return rules


def _redact_rule(content, rule, regex, group):
    def replace(match):
        start, end = match.span(group)
        relative_start = start - match.start()
        relative_end = end - match.start()
        whole = match.group(0)
        return whole[:relative_start] + "<REDACTED:%s>" % rule + whole[relative_end:]

    return regex.sub(replace, content)


def _redact_content(content):
    content = _redact_rule(content, "env_secret", ENV_ASSIGN_RE, 3)
    content = _redact_rule(content, "env_secret", ENV_QUOTED_ASSIGN_RE, 3)
    for rule, regex, group in RULES:
        content = _redact_rule(content, rule, regex, group)

    def replace_token(match):
        token = match.group(0)
        if is_high_entropy(token):
            return "<REDACTED:high_entropy>"
        return token

    return TOKEN_RE.sub(replace_token, content)


def redact_text(text):
    """Redact secrets that a model may have echoed in its response."""
    return "\n".join(_redact_content(line) for line in text.splitlines())


def sanitize_diff(diff_text):
    """Return a diff safe to send to an external API.

    Detected values are replaced. Entire files that look like .env or private
    key material are omitted line by line. Output is capped at MAX_DIFF_CHARS.
    """
    output = []
    redact_all = False
    in_hunk = False

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            redact_all = False
            in_hunk = False
            output.append(raw)
            continue

        if not in_hunk and raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                redact_all = False
            else:
                path = _unquote_git_path(path)
                if path.startswith("b/"):
                    path = path[2:]
                redact_all = is_sensitive_path(path)
            output.append(raw)
            continue

        if not in_hunk and raw.startswith("--- "):
            output.append(raw)
            continue

        if raw.startswith("@@"):
            in_hunk = True
            output.append(_redact_content(raw))
            continue

        if not in_hunk:
            output.append(raw)
            continue

        if raw.startswith(("+", "-")):
            content = raw[1:]
            if redact_all:
                output.append(raw[0] + "<REDACTED:sensitive-file>")
                continue
            if PRIVATE_KEY_RE.search(content):
                redact_all = True
                output.append(raw[0] + "<REDACTED:private-key>")
                continue
            output.append(raw[0] + _redact_content(content))
            continue

        output.append(raw)

    sanitized = "\n".join(output)
    if len(sanitized) > MAX_DIFF_CHARS:
        sanitized = (
            sanitized[:MAX_DIFF_CHARS]
            + "\n... [diff truncated by secret-guard] ...\n"
        )
    return sanitized


def get_api_key(explicit=None):
    value = explicit if explicit is not None else os.environ.get("NVIDIA_API_KEY", "")
    value = (value or "").strip()
    return value or None


def nim_chat(messages, api_key=None, model=None, timeout=DEFAULT_TIMEOUT):
    """Call the NIM chat endpoint. Returns (content, error_message)."""
    key = get_api_key(api_key)
    if not key:
        return None, "NVIDIA_API_KEY is not set"

    payload = {
        "model": model or os.environ.get("NIM_MODEL") or DEFAULT_MODEL,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 350,
        "stream": False,
    }
    request = urllib.request.Request(
        NIM_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "secret-guard/" + VERSION,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return None, "NIM request failed with HTTP %s" % exc.code
    except urllib.error.URLError as exc:
        return None, "NIM request failed: %s" % getattr(exc, "reason", "network error")
    except Exception as exc:  # timeouts, connection resets, malformed responses
        return None, "NIM request failed: %s" % type(exc).__name__

    try:
        data = json.loads(body)
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None, "NIM returned an unexpected response"

    if not isinstance(content, str) or not content.strip():
        return None, "NIM returned an empty response"
    return content.strip(), None


def parse_review(content):
    review = {"verdict": "OK", "reason": "", "message": ""}
    match = re.search(r"(?im)^\s*VERDICT:\s*(OK|BLOCK)\b", content)
    if match:
        review["verdict"] = match.group(1).upper()
    match = re.search(r"(?im)^\s*REASON:\s*(.+)$", content)
    if match:
        review["reason"] = redact_text(match.group(1).strip())
    match = re.search(r"(?ims)^\s*MESSAGE:\s*(.+)$", content)
    if match:
        review["message"] = redact_text(_clean_message(match.group(1)))
    return review


def _clean_message(text):
    text = text.strip()
    text = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_commit_message(content):
    match = re.search(r"(?ims)^\s*MESSAGE:\s*(.+)$", content)
    if match:
        content = match.group(1)
    return _clean_message(content)


def nim_review(diff_text, api_key=None, model=None, timeout=DEFAULT_TIMEOUT):
    messages = [
        {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
        {"role": "user", "content": "Staged diff:\n\n" + diff_text},
    ]
    content, error = nim_chat(messages, api_key=api_key, model=model, timeout=timeout)
    if error:
        return None, error
    return parse_review(content), None


def nim_draft(diff_text, api_key=None, model=None, timeout=DEFAULT_TIMEOUT):
    messages = [
        {"role": "system", "content": DRAFT_SYSTEM_PROMPT},
        {"role": "user", "content": "Staged diff:\n\n" + diff_text},
    ]
    content, error = nim_chat(messages, api_key=api_key, model=model, timeout=timeout)
    if error:
        return None, error
    message = extract_commit_message(content)
    if not message:
        return None, "NIM returned no commit message"
    return redact_text(message), None


def run_git(args, cwd=None, check=True):
    try:
        process = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise SecretGuardError("git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise SecretGuardError("git command timed out")

    if check and process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise SecretGuardError(detail or "git command failed")
    return process


def repo_root(cwd=None):
    process = run_git(["rev-parse", "--show-toplevel"], cwd=cwd)
    root = process.stdout.strip()
    if not root:
        raise SecretGuardError("not inside a Git repository")
    return root


def staged_diff(cwd=None):
    process = run_git(
        [
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "--unified=0",
            "--diff-filter=ACMRT",
        ],
        cwd=cwd,
    )
    return process.stdout


def _hooks_dir(root):
    process = run_git(["rev-parse", "--git-path", "hooks"], cwd=root)
    path = process.stdout.strip()
    if not path:
        raise SecretGuardError("could not locate the Git hooks directory")
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    return os.path.abspath(path)


def _shquote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def _backup_path(path):
    candidate = path + ".bak"
    index = 1
    while os.path.exists(candidate):
        candidate = "%s.bak.%d" % (path, index)
        index += 1
    return candidate


def install_hook(force=False, cwd=None):
    root = repo_root(cwd)
    hooks = _hooks_dir(root)
    try:
        os.makedirs(hooks, exist_ok=True)
    except OSError as exc:
        raise SecretGuardError("could not create hooks directory: %s" % exc)
    hook_path = os.path.join(hooks, "pre-commit")

    if os.path.exists(hook_path):
        try:
            with open(hook_path, "r", encoding="utf-8", errors="replace") as handle:
                existing = handle.read()
        except OSError as exc:
            raise SecretGuardError("could not read existing hook: %s" % exc)
        if HOOK_MARKER not in existing:
            if not force:
                raise SecretGuardError(
                    "a pre-commit hook already exists at %s; re-run with --force "
                    "to back it up and replace it" % hook_path
                )
            backup = _backup_path(hook_path)
            os.replace(hook_path, backup)

    script = os.path.realpath(__file__)
    python = sys.executable or "python3"
    content = (
        "#!/bin/sh\n"
        + HOOK_MARKER
        + "\nexec "
        + _shquote(python)
        + " "
        + _shquote(script)
        + " scan\n"
    )
    try:
        with open(hook_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.chmod(hook_path, 0o755)
    except OSError as exc:
        raise SecretGuardError("could not write hook: %s" % exc)
    return hook_path


def uninstall_hook(force=False, cwd=None):
    root = repo_root(cwd)
    hooks = _hooks_dir(root)
    hook_path = os.path.join(hooks, "pre-commit")
    if not os.path.exists(hook_path):
        return hook_path, False

    try:
        with open(hook_path, "r", encoding="utf-8", errors="replace") as handle:
            existing = handle.read()
    except OSError as exc:
        raise SecretGuardError("could not read hook: %s" % exc)

    if HOOK_MARKER not in existing and not force:
        raise SecretGuardError(
            "the pre-commit hook at %s was not installed by secret-guard; "
            "use --force to remove it anyway" % hook_path
        )
    try:
        os.remove(hook_path)
    except OSError as exc:
        raise SecretGuardError("could not remove hook: %s" % exc)
    return hook_path, True


def _print_findings(findings):
    print(
        "secret-guard: BLOCKED - potential secret(s) in staged changes:",
        file=sys.stderr,
    )
    for finding in findings:
        print(
            "  %-18s %s:%d  fingerprint=%s"
            % (finding.rule, finding.file, finding.line, finding.fingerprint),
            file=sys.stderr,
        )
    print(
        "Fix the value, unstage the file, or add 'fingerprint:%s' to "
        ".secretguardignore for a false positive." % findings[0].fingerprint,
        file=sys.stderr,
    )


def cmd_scan(args):
    root = repo_root(os.getcwd())
    diff = staged_diff(cwd=root)
    if not diff.strip():
        if getattr(args, "verbose", False):
            print("secret-guard: no staged changes to scan.", file=sys.stderr)
        return 0

    findings = scan_diff(diff, load_ignore(root))
    if findings:
        _print_findings(findings)
        return 1

    if getattr(args, "verbose", False):
        print("secret-guard: local scan clean.", file=sys.stderr)

    if args.no_ai:
        return 0

    api_key = get_api_key()
    if not api_key:
        return 0

    model = args.model or os.environ.get("NIM_MODEL") or DEFAULT_MODEL
    review, error = nim_review(
        sanitize_diff(diff), api_key=api_key, model=model, timeout=args.timeout
    )
    if error:
        print(
            "secret-guard: warning: NIM review skipped (%s); continuing." % error,
            file=sys.stderr,
        )
        return 0

    if review["verdict"] == "BLOCK":
        print(
            "secret-guard: NIM flagged a possible issue: %s"
            % (review["reason"] or "unspecified"),
            file=sys.stderr,
        )
        if review["message"]:
            print("Suggested commit message:\n%s" % review["message"])
        return 1

    if getattr(args, "verbose", False):
        print("secret-guard: NIM review clean.", file=sys.stderr)
    if review["message"]:
        print("Suggested commit message:\n%s" % review["message"])
    return 0


def cmd_install(args):
    hook_path = install_hook(force=args.force, cwd=os.getcwd())
    print("secret-guard: installed pre-commit hook at %s" % hook_path)
    return 0


def cmd_uninstall(args):
    hook_path, removed = uninstall_hook(force=args.force, cwd=os.getcwd())
    if removed:
        print("secret-guard: removed pre-commit hook at %s" % hook_path)
    else:
        print("secret-guard: no pre-commit hook found at %s" % hook_path)
    return 0


def cmd_draft(args):
    root = repo_root(os.getcwd())
    diff = staged_diff(cwd=root)
    if not diff.strip():
        print("secret-guard: no staged changes to draft a message for.", file=sys.stderr)
        return 1

    findings = scan_diff(diff, load_ignore(root))
    if findings:
        _print_findings(findings)
        return 1

    api_key = get_api_key()
    if not api_key:
        print(
            "secret-guard: error: NVIDIA_API_KEY is not set; cannot draft a message.",
            file=sys.stderr,
        )
        return 1

    model = args.model or os.environ.get("NIM_MODEL") or DEFAULT_MODEL
    message, error = nim_draft(
        sanitize_diff(diff), api_key=api_key, model=model, timeout=args.timeout
    )
    if error:
        print("secret-guard: error: %s" % error, file=sys.stderr)
        return 1

    print(message)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secret-guard",
        description="Fast local secret scanner and NIM-powered commit helper.",
    )
    parser.add_argument("--version", action="version", version="secret-guard " + VERSION)
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan staged changes (default)")
    scan.add_argument("--no-ai", action="store_true", help="skip the NVIDIA NIM stage")
    scan.add_argument("--model", default=None, help="override NIM_MODEL")
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="NIM request timeout in seconds (default: 5)",
    )
    scan.add_argument("--verbose", action="store_true", help="print extra status lines")

    install = subparsers.add_parser("install", help="install the pre-commit hook")
    install.add_argument(
        "--force",
        action="store_true",
        help="back up and replace an existing pre-commit hook",
    )

    uninstall = subparsers.add_parser("uninstall", help="remove the pre-commit hook")
    uninstall.add_argument(
        "--force",
        action="store_true",
        help="remove a pre-commit hook not installed by secret-guard",
    )

    draft = subparsers.add_parser(
        "draft-msg", help="draft a Conventional Commit message from staged changes"
    )
    draft.add_argument("--model", default=None, help="override NIM_MODEL")
    draft.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="NIM request timeout in seconds (default: 5)",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        args = argparse.Namespace(
            command="scan",
            no_ai=False,
            model=None,
            timeout=DEFAULT_TIMEOUT,
            verbose=False,
        )

    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "install":
            return cmd_install(args)
        if args.command == "uninstall":
            return cmd_uninstall(args)
        if args.command == "draft-msg":
            return cmd_draft(args)
        parser.error("unknown command")
    except SecretGuardError as exc:
        print("secret-guard: error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("secret-guard: interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
