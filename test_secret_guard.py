"""Unittest suite for secret-guard. No network access is used."""

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import secret_guard as sg


def diff_for(path, added_lines, start=1, new_file=True):
    old_header = "--- /dev/null" if new_file else "--- a/%s" % path
    lines = "".join("+%s\n" % line for line in added_lines)
    return (
        "diff --git a/{path} b/{path}\n"
        "index 1111111..2222222 100644\n"
        "{old_header}\n"
        "+++ b/{path}\n"
        "@@ -0,0 +{start},{count} @@\n"
        "{lines}"
    ).format(
        path=path,
        old_header=old_header,
        start=start,
        count=len(added_lines),
        lines=lines,
    )


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, amount=None):
        return json.dumps(self._payload).encode("utf-8")


class TestLocalDetection(unittest.TestCase):
    def rules(self, diff):
        return [finding.rule for finding in sg.scan_diff(diff)]

    def test_detects_aws_access_key(self):
        diff = diff_for("config.py", ['AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        findings = sg.scan_diff(diff)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "aws_access_key")
        self.assertEqual(findings[0].file, "config.py")
        self.assertEqual(findings[0].line, 1)

    def test_specific_rule_wins_over_env_rule_for_same_value(self):
        diff = diff_for(
            "config.py", ['AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"']
        )
        self.assertEqual(self.rules(diff), ["aws_access_key"])

    def test_detects_aws_secret_access_key(self):
        diff = diff_for(
            "settings.py",
            ['aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'],
        )
        self.assertIn("aws_secret_key", self.rules(diff))

    def test_detects_nvidia_key(self):
        diff = diff_for(
            "client.py",
            ['key = "nvapi-' + 'Zx9Qm2Lp8Rt4Vw6Yb1Nc3' + 'Kd7Sf5Gj0HkAbCdEfGh"'],
        )
        self.assertEqual(self.rules(diff), ["nvidia_api_key"])

    def test_detects_stripe_live_key(self):
        diff = diff_for(
            "billing.py", ['key = "sk_live_' + 'Zx9Qm2Lp8Rt4Vw6' + 'Yb1Nc3Kd7"']
        )
        self.assertEqual(self.rules(diff), ["stripe_secret_key"])

    def test_detects_private_key_and_suppresses_body_noise(self):
        diff = diff_for(
            "deploy/id_rsa",
            [
                "-----BEGIN RSA PRIVATE KEY-----",
                "MIIEowIBAAKCAQEA1Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk",
                "-----END RSA PRIVATE KEY-----",
            ],
        )
        findings = sg.scan_diff(diff)
        self.assertEqual([finding.rule for finding in findings], ["private_key"])

    def test_detects_env_secret(self):
        diff = diff_for(".env", ["DB_PASSWORD=hunter2supersecret"])
        self.assertEqual(self.rules(diff), ["env_secret"])

    def test_detects_high_entropy_string(self):
        diff = diff_for("data.py", ['data = "Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"'])
        self.assertEqual(self.rules(diff), ["high_entropy"])

    def test_ignores_placeholders_and_references(self):
        diff = diff_for(
            ".env",
            [
                "API_KEY=your_api_key_here",
                "DB_PASSWORD=changeme",
                "TOKEN=${GITHUB_TOKEN}",
                "SECRET=os.environ['SECRET']",
            ],
        )
        self.assertEqual(sg.scan_diff(diff), [])

    def test_does_not_flag_hyphenated_product_message(self):
        diff = diff_for(
            "tool.py",
            ['"secret-guard: warning: NIM review skipped; continuing."'],
        )
        self.assertEqual(sg.scan_diff(diff), [])

    def test_detects_hyphenated_env_key(self):
        diff = diff_for("config.yml", ["db-password: hunter2supersecret"])
        self.assertEqual([finding.rule for finding in sg.scan_diff(diff)], ["env_secret"])

    def test_detects_quoted_json_env_key(self):
        diff = diff_for("config.json", ['"client-secret": "hunter2supersecret",'])
        self.assertEqual([finding.rule for finding in sg.scan_diff(diff)], ["env_secret"])

    def test_clean_diff_has_no_findings(self):
        diff = diff_for("app.py", ['print("hello world")', "x = 1 + 2"])
        self.assertEqual(sg.scan_diff(diff), [])

    def test_reports_correct_line_number_after_hunk_start(self):
        diff = diff_for("app.py", ["ok = True", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'], start=40)
        findings = sg.scan_diff(diff)
        self.assertEqual(findings[0].line, 41)

    def test_added_line_starting_with_plus_is_not_treated_as_header(self):
        diff = diff_for("app.c", ['++ AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        findings = sg.scan_diff(diff)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "aws_access_key")

    def test_added_line_starting_with_triple_plus_is_not_treated_as_header(self):
        diff = diff_for("app.c", ['+++AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        findings = sg.scan_diff(diff)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "aws_access_key")

    def test_entropy_skip_for_lockfiles(self):
        token = "Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"
        diff = diff_for("package-lock.json", ['"integrity": "%s"' % token])
        self.assertEqual(sg.scan_diff(diff), [])

    def test_finding_repr_does_not_leak_value(self):
        finding = sg.Finding("aws_access_key", "a.py", 1, "AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", repr(finding))
        self.assertIn(finding.fingerprint, repr(finding))

    def test_shannon_entropy(self):
        self.assertAlmostEqual(sg.shannon_entropy("Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"), 5.0)
        self.assertEqual(sg.shannon_entropy(""), 0.0)


class TestAllowlist(unittest.TestCase):
    def test_path_glob_ignores_file(self):
        ignore = sg.IgnoreRules()
        ignore.paths.append("tests/*")
        diff = diff_for("tests/fixture.py", ['AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        self.assertEqual(sg.scan_diff(diff, ignore), [])

    def test_fingerprint_ignores_finding(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        ignore = sg.IgnoreRules()
        ignore.fingerprints.add(sg.fingerprint(secret))
        diff = diff_for("config.py", ['AWS_KEY = "%s"' % secret])
        self.assertEqual(sg.scan_diff(diff, ignore), [])

    def test_rule_ignore_suppresses_entire_rule(self):
        ignore = sg.IgnoreRules()
        ignore.rules.add("env_secret")
        diff = diff_for(".env", ["DB_PASSWORD=hunter2supersecret"])
        self.assertEqual(sg.scan_diff(diff, ignore), [])

    def test_bare_pattern_is_treated_as_path(self):
        ignore = sg.IgnoreRules()
        ignore.paths.append("*.env")
        diff = diff_for("production.env", ["DB_PASSWORD=hunter2supersecret"])
        self.assertEqual(sg.scan_diff(diff, ignore), [])

    def test_load_ignore_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(
                os.path.join(directory, ".secretguardignore"), "w", encoding="utf-8"
            ) as handle:
                handle.write(
                    "# comment\n"
                    "path:tests/*\n"
                    "rule:high_entropy\n"
                    "fingerprint:0123456789ab\n"
                    "fingerprint:short\n"
                )
            ignore = sg.load_ignore(directory)
        self.assertEqual(ignore.paths, ["tests/*"])
        self.assertEqual(ignore.rules, {"high_entropy"})
        self.assertEqual(ignore.fingerprints, {"0123456789ab"})

    def test_ignore_file_is_never_scanned(self):
        diff = diff_for(".secretguardignore", ["match:AKIAIOSFODNN7EXAMPLE"])
        self.assertEqual(sg.scan_diff(diff), [])


class TestCommandFlows(unittest.TestCase):
    def scan_args(self, **overrides):
        values = dict(no_ai=False, model=None, timeout=5.0, verbose=False)
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_scan_blocks_locally_and_never_calls_nim(self):
        diff = diff_for("config.py", ['AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        with mock.patch.object(sg, "repo_root", return_value="/repo"), \
             mock.patch.object(sg, "staged_diff", return_value=diff), \
             mock.patch.object(sg, "load_ignore", return_value=sg.IgnoreRules()), \
             mock.patch.object(sg, "get_api_key", return_value="test-key"), \
             mock.patch.object(sg, "nim_review") as review, \
             contextlib.redirect_stderr(io.StringIO()):
            code = sg.cmd_scan(self.scan_args())
        self.assertEqual(code, 1)
        review.assert_not_called()

    def test_scan_fails_open_when_nim_times_out(self):
        diff = diff_for("app.py", ['print("hello")'])
        stderr = io.StringIO()
        with mock.patch.object(sg, "repo_root", return_value="/repo"), \
             mock.patch.object(sg, "staged_diff", return_value=diff), \
             mock.patch.object(sg, "load_ignore", return_value=sg.IgnoreRules()), \
             mock.patch.object(sg, "get_api_key", return_value="test-key"), \
             mock.patch.object(
                 sg, "nim_review", return_value=(None, "NIM request failed: TimeoutError")
             ), \
             contextlib.redirect_stderr(stderr):
            code = sg.cmd_scan(self.scan_args())
        self.assertEqual(code, 0)
        self.assertIn("continuing", stderr.getvalue())

    def test_scan_no_ai_skips_nim(self):
        diff = diff_for("app.py", ['print("hello")'])
        with mock.patch.object(sg, "repo_root", return_value="/repo"), \
             mock.patch.object(sg, "staged_diff", return_value=diff), \
             mock.patch.object(sg, "load_ignore", return_value=sg.IgnoreRules()), \
             mock.patch.object(sg, "nim_review") as review:
            code = sg.cmd_scan(self.scan_args(no_ai=True))
        self.assertEqual(code, 0)
        review.assert_not_called()

    def test_draft_refuses_to_send_diff_with_detected_secret(self):
        diff = diff_for("config.py", ['AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])
        args = argparse.Namespace(model=None, timeout=5.0)
        with mock.patch.object(sg, "repo_root", return_value="/repo"), \
             mock.patch.object(sg, "staged_diff", return_value=diff), \
             mock.patch.object(sg, "load_ignore", return_value=sg.IgnoreRules()), \
             mock.patch.object(sg, "get_api_key", return_value="test-key"), \
             mock.patch.object(sg, "nim_draft") as draft, \
             contextlib.redirect_stderr(io.StringIO()):
            code = sg.cmd_draft(args)
        self.assertEqual(code, 1)
        draft.assert_not_called()


class TestSanitization(unittest.TestCase):
    def test_redacts_aws_key_in_code(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        diff = diff_for("app.py", ['AWS_KEY = "%s"' % secret])
        sanitized = sg.sanitize_diff(diff)
        self.assertNotIn(secret, sanitized)
        self.assertIn("<REDACTED:aws_access_key>", sanitized)

    def test_redacts_env_file_entirely(self):
        diff = diff_for(".env", ["DB_PASSWORD=hunter2supersecret"])
        sanitized = sg.sanitize_diff(diff)
        self.assertNotIn("hunter2supersecret", sanitized)
        self.assertIn("<REDACTED:sensitive-file>", sanitized)

    def test_redacts_private_key_named_file_entirely(self):
        body = "MIIEowIBAAKCAQEA1Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"
        diff = diff_for(
            "deploy/id_rsa",
            ["-----BEGIN RSA PRIVATE KEY-----", body, "-----END RSA PRIVATE KEY-----"],
        )
        sanitized = sg.sanitize_diff(diff)
        self.assertNotIn(body, sanitized)
        self.assertIn("<REDACTED:sensitive-file>", sanitized)

    def test_redacts_private_key_embedded_in_other_file(self):
        body = "MIIEowIBAAKCAQEA1Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"
        diff = diff_for(
            "notes.txt",
            ["-----BEGIN RSA PRIVATE KEY-----", body, "-----END RSA PRIVATE KEY-----"],
        )
        sanitized = sg.sanitize_diff(diff)
        self.assertNotIn(body, sanitized)
        self.assertIn("<REDACTED:private-key>", sanitized)

    def test_redacts_high_entropy_token(self):
        token = "Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd7Sf5Gj0Hk"
        sanitized = sg.sanitize_diff(diff_for("data.py", ['data = "%s"' % token]))
        self.assertNotIn(token, sanitized)
        self.assertIn("<REDACTED:high_entropy>", sanitized)

    def test_redacts_short_env_value_even_if_below_block_threshold(self):
        sanitized = sg.sanitize_diff(diff_for("config.py", ['password = "abc"']))
        self.assertNotIn('"abc"', sanitized)
        self.assertIn("<REDACTED:env_secret>", sanitized)

    def test_redacts_quoted_json_short_value(self):
        sanitized = sg.sanitize_diff(
            diff_for("config.json", ['"client-secret": "abc",'])
        )
        self.assertNotIn('"abc"', sanitized)
        self.assertIn("<REDACTED:env_secret>", sanitized)

    def test_truncates_large_diffs(self):
        diff = diff_for("big.txt", ["line %d" % index for index in range(3000)])
        sanitized = sg.sanitize_diff(diff)
        self.assertLessEqual(len(sanitized), sg.MAX_DIFF_CHARS + 100)
        self.assertIn("diff truncated", sanitized)


class TestNim(unittest.TestCase):
    def test_nim_review_success_and_sanitized_request(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        diff = diff_for("app.py", ['AWS_KEY = "%s"' % secret])
        sanitized = sg.sanitize_diff(diff)
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["data"] = request.data
            captured["headers"] = dict(request.header_items())
            captured["timeout"] = timeout
            return FakeResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    "VERDICT: OK\n"
                                    "REASON: no additional issues\n"
                                    "MESSAGE: feat(scan): add local secret detection"
                                )
                            }
                        }
                    ]
                }
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            review, error = sg.nim_review(
                sanitized,
                api_key="unitkey",
                model="test-model",
                timeout=5.0,
            )

        self.assertIsNone(error)
        self.assertEqual(review["verdict"], "OK")
        self.assertEqual(review["reason"], "no additional issues")
        self.assertEqual(review["message"], "feat(scan): add local secret detection")
        self.assertEqual(captured["url"], sg.NIM_URL)
        self.assertEqual(captured["timeout"], 5.0)
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer unitkey")

        request_text = captured["data"].decode("utf-8")
        payload = json.loads(request_text)
        self.assertEqual(payload["model"], "test-model")
        self.assertNotIn(secret, request_text)
        self.assertNotIn("unitkey", request_text)

    def test_nim_review_block_verdict(self):
        def fake_urlopen(request, timeout=None):
            return FakeResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    "VERDICT: BLOCK\n"
                                    "REASON: user input reaches eval()\n"
                                    "MESSAGE: fix(eval): remove unsafe eval call"
                                )
                            }
                        }
                    ]
                }
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            review, error = sg.nim_review("diff", api_key="test-key")

        self.assertIsNone(error)
        self.assertEqual(review["verdict"], "BLOCK")
        self.assertIn("eval", review["reason"])

    def test_nim_timeout_fails_open_with_error(self):
        def fake_urlopen(request, timeout=None):
            raise TimeoutError("timed out")

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            review, error = sg.nim_review("diff", api_key="test-key")

        self.assertIsNone(review)
        self.assertIn("NIM request failed", error)

    def test_nim_http_error_is_reported(self):
        import urllib.error

        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(sg.NIM_URL, 401, "Unauthorized", {}, None)

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            review, error = sg.nim_review("diff", api_key="test-key")

        self.assertIsNone(review)
        self.assertIn("HTTP 401", error)

    def test_nim_missing_key(self):
        review, error = sg.nim_review("diff", api_key="")
        self.assertIsNone(review)
        self.assertIn("NVIDIA_API_KEY", error)

    def test_nim_draft_cleans_code_fence(self):
        def fake_urlopen(request, timeout=None):
            return FakeResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "content": "```\nfix(scan): redact env values\n```"
                            }
                        }
                    ]
                }
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            message, error = sg.nim_draft("diff", api_key="test-key")

        self.assertIsNone(error)
        self.assertEqual(message, "fix(scan): redact env values")

    def test_parse_review_defaults_to_ok(self):
        review = sg.parse_review("VERDICT: OK\nMESSAGE: chore: tidy up")
        self.assertEqual(review["verdict"], "OK")
        self.assertEqual(review["message"], "chore: tidy up")

    def test_parse_review_without_verdict_fails_open(self):
        review = sg.parse_review("MESSAGE: docs: explain setup")
        self.assertEqual(review["verdict"], "OK")
        self.assertEqual(review["message"], "docs: explain setup")

    def test_model_output_is_redacted_before_display(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        review = sg.parse_review(
            "VERDICT: OK\n"
            "REASON: saw %s in the diff\n"
            "MESSAGE: fix(config): remove %s" % (secret, secret)
        )
        self.assertNotIn(secret, review["reason"])
        self.assertNotIn(secret, review["message"])
        self.assertIn("<REDACTED:aws_access_key>", review["reason"])


@unittest.skipUnless(shutil.which("git"), "git is required for hook tests")
class TestHookInstall(unittest.TestCase):
    def make_repo(self):
        directory = tempfile.mkdtemp(prefix="secret-guard-test-")
        self.addCleanup(shutil.rmtree, directory, True)
        subprocess.run(["git", "init", "-q", directory], check=True)
        return directory

    def test_install_creates_executable_hook_and_uninstall_removes_it(self):
        root = self.make_repo()
        hook_path = sg.install_hook(cwd=root)
        self.assertTrue(os.path.isfile(hook_path))
        self.assertTrue(os.access(hook_path, os.X_OK))
        with open(hook_path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn(sg.HOOK_MARKER, content)
        self.assertIn(" scan", content)

        removed_path, removed = sg.uninstall_hook(cwd=root)
        self.assertTrue(removed)
        self.assertEqual(removed_path, hook_path)
        self.assertFalse(os.path.exists(hook_path))

    def test_install_refuses_to_clobber_unknown_hook(self):
        root = self.make_repo()
        hooks_dir = os.path.join(root, ".git", "hooks")
        hook_path = os.path.join(hooks_dir, "pre-commit")
        with open(hook_path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho existing\n")
        os.chmod(hook_path, 0o755)

        with self.assertRaises(sg.SecretGuardError):
            sg.install_hook(cwd=root)

        sg.install_hook(force=True, cwd=root)
        backups = [name for name in os.listdir(hooks_dir) if ".bak" in name]
        self.assertEqual(len(backups), 1)
        with open(os.path.join(hooks_dir, backups[0]), "r", encoding="utf-8") as handle:
            self.assertIn("echo existing", handle.read())

    def test_uninstall_refuses_unknown_hook_without_force(self):
        root = self.make_repo()
        hook_path = os.path.join(root, ".git", "hooks", "pre-commit")
        with open(hook_path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho existing\n")

        with self.assertRaises(sg.SecretGuardError):
            sg.uninstall_hook(cwd=root)

        _, removed = sg.uninstall_hook(force=True, cwd=root)
        self.assertTrue(removed)
        self.assertFalse(os.path.exists(hook_path))


if __name__ == "__main__":
    unittest.main()
