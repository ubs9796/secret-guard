# secret-guard

A fast, zero-dependency Python 3 CLI that helps stop secrets before they enter
Git history and drafts [Conventional Commit](https://www.conventionalcommits.org/)
messages with the NVIDIA NIM API.

It works in two stages:

1. **Local guard (<100 ms, offline).** Scans `git diff --cached` with regexes
   and high-entropy detection. If it finds a likely secret, it blocks the commit
   and prints the file, line, rule, and a safe fingerprint. No network call is
   made. On the development machine used for this build, a synthetic diff with
   2,000 added lines scanned in about 57 ms; typical staged diffs are much
   smaller.
2. **NIM review (optional, best effort).** If the local scan is clean and
   `NVIDIA_API_KEY` is set, it sends a **sanitized** diff to the NVIDIA NIM API
   with a strict 5-second timeout. The model looks for subtle security issues
   and suggests a commit message. Timeouts and outages fail open with a warning,
   so a developer is never blocked by the network.

Only the Python standard library is used: no pip packages, no containers, no
daemons.

## Requirements

- Python 3.8 or newer
- Git
- Optional: an NVIDIA API key from <https://build.nvidia.com/> for Stage 2

## Install

```bash
cd secret-guard
bash install.sh
```

The installer symlinks `secret_guard.py` to `~/.local/bin/secret-guard` and
makes it executable. If `~/.local/bin` is not on your `PATH`, add it:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Install the Git hook in any repository:

```bash
cd /path/to/repo
secret-guard install
```

This writes `.git/hooks/pre-commit`. Existing hooks are not clobbered; use
`secret-guard install --force` to back one up and replace it. To install the
symlink and the current repository's hook in one step:

```bash
bash install.sh --hook
```

Remove the hook:

```bash
secret-guard uninstall
```

## Usage

```bash
secret-guard scan          # scan staged changes (also the default with no args)
secret-guard scan --no-ai  # skip Stage 2 entirely
secret-guard draft-msg     # print a Conventional Commit message for the staged diff
secret-guard install       # install the pre-commit hook
secret-guard uninstall     # remove it
```

Common options:

```text
--model MODEL   Override NIM_MODEL for this run
--timeout SECS  NIM timeout (default: 5)
--verbose       Print extra status information to stderr
--force         Used by install/uninstall when replacing or removing a hook
```

Examples:

```bash
# Commit as usual; the hook runs Stage 1, then Stage 2 if a key is set.
git add .
git commit -m "feat(cli): add scan command"

# Prefill a message from the staged diff (stops if a secret is detected).
git add .
git commit -m "$(secret-guard draft-msg)"
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success / no blocking secret |
| `1` | A local or NIM finding blocked the operation |
| `2` | Usage, Git, or repository error |
| `130` | Interrupted |

## Configuration

| Environment variable | Purpose | Default |
| --- | --- | --- |
| `NVIDIA_API_KEY` | NIM API key. Read from the environment only. | unset (Stage 2 skipped) |
| `NIM_MODEL` | NIM model name | `meta/llama-3.3-70b-instruct` |

The key is sent only in the `Authorization: Bearer ...` request header and is
never printed, logged, or included in the request body.

### `.secretguardignore`

Place this file at the repository root to suppress false positives. Lines can be:

```gitignore
# Ignore an entire path or glob
path:tests/fixtures/*
*.example.env

# Ignore one detector for the whole repository
rule:high_entropy

# Ignore a specific finding by its printed fingerprint (recommended)
fingerprint:3a5f9c2d1b7e

# Last resort: ignore values containing a substring (do not use for real secrets)
match:example-false-positive
```

`fingerprint:` is the first 12 hex characters of the SHA-256 of the matched
value. It lets you allowlist a false positive without writing the raw value into
another tracked file. The file itself is never scanned.

## What Stage 1 detects

- AWS access key IDs and `aws_secret_access_key` assignments
- NVIDIA keys (`nvapi-...`)
- Stripe live secret/restricted keys (`sk_live_...`, `rk_live_...`)
- PEM private key headers (`BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`,
  and similar), including suppressing noisy body lines
- `.env`-style assignments such as `PASSWORD=`, `TOKEN=`, `API_KEY=`, `SECRET=`,
  and JSON/YAML/Python equivalents
- Generic high-entropy tokens (Shannon entropy >= 4.5 over 24+ characters),
  with lockfiles, minified assets, maps, and certificate files skipped

Placeholders such as `${GITHUB_TOKEN}`, `changeme`, `your_..._here`, and
`os.environ[...]` are ignored to reduce noise.

## How the NIM request is protected

Before any API call, `sanitize_diff()`:

- Replaces every detected secret with `<REDACTED:rule>`
- Replaces high-entropy tokens with `<REDACTED:high_entropy>`
- Omits the contents of `.env`-like and private-key-like files entirely
- Redacts private key blocks even when they appear inside another file
- Caps the diff at 16,000 characters

If Stage 1 finds a secret, Stage 2 never runs at all. `draft-msg` also refuses
to run until the finding is fixed or allowlisted.

## Test

```bash
cd secret-guard
python3 -m unittest -v
```

The suite covers local detection, allowlisting, sanitization, mocked NIM
success/timeout/HTTP failures, and hook install/uninstall. It does not use the
network or a real API key.

## Security and limitations

- When `NVIDIA_API_KEY` is set, the **sanitized diff leaves your machine** for
  NVIDIA's API. It contains code changes, but detected secrets are replaced and
  sensitive files are omitted. If sending source code to a third party is not
  acceptable, unset `NVIDIA_API_KEY` or use `secret-guard scan --no-ai`.
- Regex detection is useful but not exhaustive. Treat a clean scan as a safety
  net, not a guarantee.
- The NIM review is advisory and model-dependent. A `VERDICT: BLOCK` response
  blocks the commit; an API failure does not. If a model block is a false
  positive, use `git commit --no-verify` or adjust the local hook.
- A `match:` allowlist entry can put a false-positive value in a tracked file.
  Prefer `fingerprint:` unless you are certain the value is not sensitive.
- Git hooks can be bypassed with `git commit --no-verify`. This tool cannot
  prevent a determined developer from skipping it; pair it with server-side
  scanning and repository secret scanning.
- If a secret has already been committed or pushed, rotate it. Removing it from
  the latest commit is not enough; assume it is compromised.
- The hook stores the absolute path to the Python interpreter and this script.
  Re-run `secret-guard install` if you move the installation or recreate the
  virtual environment.

## Uninstall

```bash
secret-guard uninstall            # inside a repository
rm ~/.local/bin/secret-guard      # remove the CLI symlink
```

## License

MIT License. Copyright (c) 2026 bsloopstudio.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Distribution

`secret_guard.py` is the entire runtime. To distribute it, copy that file (and
optionally `install.sh`) into a repository, a release archive, or an internal
package. No dependency resolution is needed. Keep the executable bit set:

```bash
chmod 755 secret_guard.py
```
