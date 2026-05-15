# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the YAML-driven secrets detection engine.

All tests run without network access. The scanner itself is exercised as a
pure function — no HTTP, no database.
"""
from __future__ import annotations

import pathlib
import re
import textwrap

import pytest
import yaml

from nis2scan.secrets import (
    SecretsDetector,
    _FALLBACK_PATTERNS,
    _PATTERNS_FILE,
    _load_patterns,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detector(tmp_path: pathlib.Path, yaml_content: str) -> SecretsDetector:
    f = tmp_path / "patterns.yaml"
    f.write_text(yaml_content, encoding="utf-8")
    return SecretsDetector(patterns_file=f)


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

class TestYamlLoading:
    def test_default_patterns_file_exists(self) -> None:
        assert _PATTERNS_FILE.exists(), f"Pattern file missing: {_PATTERNS_FILE}"

    def test_default_file_is_valid_yaml(self) -> None:
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        assert "patterns" in data

    def test_default_file_has_at_least_ten_patterns(self) -> None:
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        assert len(data["patterns"]) >= 10

    def test_each_pattern_entry_has_required_keys(self) -> None:
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        required = {"id", "pattern", "description", "severity"}
        for entry in data["patterns"]:
            missing = required - set(entry.keys())
            assert not missing, f"Pattern {entry.get('id')} missing keys: {missing}"

    def test_severity_values_are_valid(self) -> None:
        valid = {"critical", "high", "medium", "low"}
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        for entry in data["patterns"]:
            assert entry["severity"] in valid, (
                f"Pattern {entry['id']} has invalid severity {entry['severity']!r}"
            )

    def test_all_patterns_compile(self) -> None:
        patterns = _load_patterns(_PATTERNS_FILE)
        assert len(patterns) >= 10
        for pid, compiled in patterns.items():
            assert isinstance(compiled, re.Pattern), f"{pid} did not compile"

    def test_ids_are_unique(self) -> None:
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        ids = [e["id"] for e in data["patterns"]]
        assert len(ids) == len(set(ids)), "Duplicate pattern ids found"

    def test_custom_patterns_file_is_used(self, tmp_path: pathlib.Path) -> None:
        content = textwrap.dedent("""\
            patterns:
              - id: test_only
                pattern: 'TESTTOKEN[0-9]{4}'
                description: Test
                severity: high
        """)
        det = _detector(tmp_path, content)
        assert "test_only" in det.patterns

    def test_missing_file_falls_back_to_hardcoded(self, tmp_path: pathlib.Path) -> None:
        missing = tmp_path / "no_such_file.yaml"
        det = SecretsDetector(patterns_file=missing)
        assert det.patterns is _FALLBACK_PATTERNS

    def test_invalid_regex_entry_is_skipped(self, tmp_path: pathlib.Path) -> None:
        content = textwrap.dedent("""\
            patterns:
              - id: bad_regex
                pattern: '[invalid('
                description: Bad
                severity: low
              - id: good_regex
                pattern: 'GOOD[0-9]+'
                description: Good
                severity: low
        """)
        det = _detector(tmp_path, content)
        assert "bad_regex" not in det.patterns
        assert "good_regex" in det.patterns

    def test_flags_ignorecase_applied(self, tmp_path: pathlib.Path) -> None:
        content = textwrap.dedent("""\
            patterns:
              - id: case_test
                pattern: 'mysecret'
                description: Test
                severity: low
                flags: [IGNORECASE]
        """)
        det = _detector(tmp_path, content)
        hits = det.scan_content("MYSECRET123", source="test")
        assert any(h["type"] == "case_test" for h in hits)


# ---------------------------------------------------------------------------
# SecretsDetector.scan_content
# ---------------------------------------------------------------------------

class TestScanContent:
    def test_no_findings_in_clean_content(self) -> None:
        det = SecretsDetector()
        assert det.scan_content("Hello, world!") == []

    def test_aws_access_key_detected(self) -> None:
        det = SecretsDetector()
        content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        hits = det.scan_content(content, source="env")
        assert any(h["type"] == "aws_access_key_id" for h in hits)

    def test_github_classic_pat_detected(self) -> None:
        det = SecretsDetector()
        content = "token = ghp_" + "a" * 36
        hits = det.scan_content(content)
        assert any(h["type"] == "github_classic_pat" for h in hits)

    def test_github_fine_grained_pat_detected(self) -> None:
        det = SecretsDetector()
        content = "github_pat_" + "b" * 82
        hits = det.scan_content(content)
        assert any(h["type"] == "github_fine_grained_pat" for h in hits)

    def test_github_oauth_token_detected(self) -> None:
        det = SecretsDetector()
        content = "gho_" + "c" * 36
        hits = det.scan_content(content)
        assert any(h["type"] == "github_oauth_token" for h in hits)

    def test_private_key_header_detected(self) -> None:
        det = SecretsDetector()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
        hits = det.scan_content(content)
        assert any(h["type"] == "private_key_pem" for h in hits)

    def test_jwt_detected(self) -> None:
        det = SecretsDetector()
        # Fake but structurally valid JWT (three base64url segments)
        content = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        hits = det.scan_content(content)
        assert any(h["type"] == "jwt_token" for h in hits)

    def test_preview_truncated_to_50_chars(self) -> None:
        det = SecretsDetector()
        content = "AKIAIOSFODNN7EXAMPLE" + "X" * 100
        hits = det.scan_content(content)
        aws = [h for h in hits if h["type"] == "aws_access_key_id"]
        assert aws, "Expected AWS key hit"
        assert len(aws[0]["preview"]) <= 53  # 50 chars + "..."

    def test_source_field_preserved(self) -> None:
        det = SecretsDetector()
        content = "AKIAIOSFODNN7EXAMPLE"
        hits = det.scan_content(content, source="https://example.com/config.js")
        assert hits[0]["source"] == "https://example.com/config.js"

    def test_position_is_correct(self) -> None:
        det = SecretsDetector()
        prefix = "key="
        content = prefix + "AKIAIOSFODNN7EXAMPLE"
        hits = det.scan_content(content)
        aws = [h for h in hits if h["type"] == "aws_access_key_id"]
        assert aws[0]["position"] == len(prefix)

    def test_multiple_secrets_in_one_document(self) -> None:
        det = SecretsDetector()
        content = (
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "GITHUB=ghp_" + "a" * 36 + "\n"
        )
        hits = det.scan_content(content)
        types = {h["type"] for h in hits}
        assert "aws_access_key_id" in types
        assert "github_classic_pat" in types


# ---------------------------------------------------------------------------
# SecretsDetector.reload
# ---------------------------------------------------------------------------

class TestReload:
    def test_reload_returns_pattern_count(self, tmp_path: pathlib.Path) -> None:
        content = textwrap.dedent("""\
            patterns:
              - id: tok_a
                pattern: 'TOKEN_A[0-9]+'
                description: A
                severity: low
        """)
        f = tmp_path / "p.yaml"
        f.write_text(content)
        det = SecretsDetector(patterns_file=f)
        assert det.reload() == 1

    def test_reload_picks_up_new_patterns(self, tmp_path: pathlib.Path) -> None:
        v1 = textwrap.dedent("""\
            patterns:
              - id: tok_v1
                pattern: 'TOKEN_V1'
                description: V1
                severity: low
        """)
        f = tmp_path / "p.yaml"
        f.write_text(v1)
        det = SecretsDetector(patterns_file=f)

        v2 = textwrap.dedent("""\
            patterns:
              - id: tok_v1
                pattern: 'TOKEN_V1'
                description: V1
                severity: low
              - id: tok_v2
                pattern: 'TOKEN_V2'
                description: V2
                severity: high
        """)
        f.write_text(v2)
        det.reload()
        assert "tok_v2" in det.patterns


# ---------------------------------------------------------------------------
# Pattern coverage — spot-check modern token formats
# ---------------------------------------------------------------------------

class TestModernPatternCoverage:
    """Verify the YAML covers token formats that postdate the original hardcoded set."""

    def _ids(self) -> set[str]:
        data = yaml.safe_load(_PATTERNS_FILE.read_text())
        return {e["id"] for e in data["patterns"]}

    def test_github_fine_grained_pat_is_present(self) -> None:
        assert "github_fine_grained_pat" in self._ids()

    def test_github_app_tokens_present(self) -> None:
        ids = self._ids()
        assert "github_oauth_token" in ids
        assert "github_app_installation_token" in ids

    def test_gitlab_tokens_present(self) -> None:
        ids = self._ids()
        assert "gitlab_pat" in ids

    def test_openai_keys_present(self) -> None:
        ids = self._ids()
        assert "openai_api_key" in ids or "openai_api_key_v2" in ids

    def test_slack_tokens_present(self) -> None:
        ids = self._ids()
        assert "slack_bot_token" in ids
