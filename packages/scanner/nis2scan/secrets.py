# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Secrets Detection and WHOIS Monitoring

Secret patterns are loaded from secret_patterns.yaml next to this module.
To add or update patterns, edit that file — no code change required.
If the YAML file is missing, a minimal hardcoded fallback is used and a
WARNING is logged so operators notice the degraded state.
"""
from __future__ import annotations

import re
import logging
import pathlib
from datetime import datetime
from typing import Any

import yaml

logger = logging.getLogger("nis2scan")

# Path to the pattern file shipped alongside this module.
_PATTERNS_FILE = pathlib.Path(__file__).parent / "secret_patterns.yaml"

# Minimal fallback compiled at import time so the scanner never crashes
# even if the YAML file is absent (e.g. partial installation).
_FALLBACK_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_pem": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    "github_classic_pat": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+"),
}

_FLAG_MAP: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


def _load_patterns(path: pathlib.Path) -> dict[str, re.Pattern[str]]:
    """Load and compile regex patterns from a YAML pattern file.

    Returns a dict keyed by pattern id. Raises nothing — callers handle
    missing / malformed files and fall back to _FALLBACK_PATTERNS.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = raw.get("patterns", [])
    compiled: dict[str, re.Pattern[str]] = {}
    for entry in entries:
        pid = entry["id"]
        flags = 0
        for flag_name in entry.get("flags", []):
            flags |= _FLAG_MAP.get(flag_name, 0)
        try:
            compiled[pid] = re.compile(entry["pattern"], flags)
        except re.error as exc:
            logger.warning("secret_patterns: skipping %r — invalid regex: %s", pid, exc)
    return compiled


def _load_patterns_from_file(
    path: pathlib.Path = _PATTERNS_FILE,
) -> tuple[dict[str, re.Pattern[str]], pathlib.Path]:
    """Return (patterns_dict, source_path).

    Falls back to _FALLBACK_PATTERNS if the file is missing or unreadable,
    logging a WARNING so operators notice the degraded state.
    """
    if not path.exists():
        logger.warning(
            "secrets: pattern file not found at %s — using minimal hardcoded fallback. "
            "Secret detection coverage is reduced.",
            path,
        )
        return _FALLBACK_PATTERNS, path

    try:
        patterns = _load_patterns(path)
        logger.debug(
            "secrets: loaded %d patterns from %s", len(patterns), path
        )
        return patterns, path
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "secrets: failed to load pattern file %s (%s) — using minimal hardcoded fallback.",
            path,
            exc,
        )
        return _FALLBACK_PATTERNS, path


class SecretsDetector:
    """Detects leaked secrets in HTTP responses.

    Patterns are loaded from ``secret_patterns.yaml`` adjacent to this module.
    Pass a custom ``patterns_file`` path to override (useful for testing or
    per-deployment customisation).
    """

    def __init__(self, patterns_file: pathlib.Path | None = None) -> None:
        source = patterns_file or _PATTERNS_FILE
        self.patterns, self._patterns_file = _load_patterns_from_file(source)
        logger.info(
            "SecretsDetector: %d patterns loaded from %s",
            len(self.patterns),
            self._patterns_file,
        )

    def reload(self) -> int:
        """Re-read the pattern file and recompile patterns.

        Returns the new pattern count. Useful for long-running scanner
        processes that want to pick up pattern updates without restart.
        """
        self.patterns, _ = _load_patterns_from_file(self._patterns_file)
        logger.info(
            "SecretsDetector: reloaded — %d patterns active", len(self.patterns)
        )
        return len(self.patterns)

    def scan_content(
        self, content: str, source: str = "unknown"
    ) -> list[dict[str, Any]]:
        """Scan content for leaked secrets.

        Returns a list of finding dicts. The ``preview`` field truncates the
        match to 50 chars to avoid storing the full secret in the database.
        """
        findings: list[dict[str, Any]] = []
        for secret_type, pattern in self.patterns.items():
            for match in pattern.finditer(content):
                findings.append(
                    {
                        "type": secret_type,
                        "source": source,
                        "preview": match.group(0)[:50] + "...",
                        "position": match.start(),
                    }
                )
        return findings


class WHOISMonitor:
    """Monitors domain expiration dates."""

    def __init__(self, warning_days: int = 30):
        self.warning_days = warning_days

    def check_domain_expiry(self, domain: str) -> dict[str, Any]:
        """Check domain expiration date using python-whois.

        Returns: {domain, expiry_date, days_remaining, warning, error}
        """
        result: dict[str, Any] = {
            "domain": domain,
            "expiry_date": None,
            "days_remaining": None,
            "warning": False,
            "error": None,
        }

        try:
            import whois

            w = whois.whois(domain)
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]

            if expiry:
                result["expiry_date"] = (
                    expiry.isoformat() if hasattr(expiry, "isoformat") else str(expiry)
                )
                if isinstance(expiry, datetime):
                    days_left = (expiry - datetime.now()).days
                    result["days_remaining"] = days_left
                    if days_left < self.warning_days:
                        result["warning"] = True

        except ImportError:
            result["error"] = "python-whois not installed"
            logger.warning("python-whois not installed. Install with: pip install python-whois")
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

        return result
