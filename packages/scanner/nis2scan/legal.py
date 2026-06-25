# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Regional and Legal Compliance Checks
Validates security.txt, Italian P.IVA, Privacy Policy, Cookie Banners
"""
import asyncio
import ipaddress
import re
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("nis2scan")

# L5: cap concurrent headless-Chromium launches per scan. Each browser spawns
# many processes; an unbounded fan-out (up to the scanner's `concurrency`,
# default 20) can pin every scan slot in 30s renders and spike memory.
_MAX_CONCURRENT_PLAYWRIGHT = 2

# Internal/metadata hostnames Playwright must never be steered toward.
_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "169.254.169.254",
    "kubernetes",
    "kubernetes.default",
}


def _is_blocked_host(hostname: str) -> bool:
    """True for internal/metadata names or private/reserved IP literals.

    Used to (a) refuse to pin Playwright at a non-public IP and (b) abort any
    sub-resource request to an obviously-internal host while rendering.
    """
    if not hostname:
        return True
    h = hostname.strip().lower().rstrip(".")
    if h in _BLOCKED_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False  # a normal public hostname — allowed
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


class LegalChecker:
    """Handles regional/legal compliance checks"""

    def __init__(self):
        # Italian P.IVA regex: 11 digits
        self.piva_pattern = re.compile(r'P\.?\s*IVA:?\s*(\d{11})')

        # Privacy policy keywords (case insensitive)
        self.privacy_keywords = ['privacy policy', 'informativa privacy', 'privacy']

        # Cookie banner keywords (multilingual)
        self.cookie_keywords = [
            'cookie', 'accetta', 'accetto', 'consenso', 'accept cookies',
            'cookie policy', 'gestisci cookie', 'manage cookies'
        ]

        # Gate concurrent Playwright launches (see _MAX_CONCURRENT_PLAYWRIGHT).
        # Constructed here (no running loop needed in 3.10+); binds to the loop on
        # first acquire — one LegalChecker per Scanner per Celery-task loop.
        self._playwright_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PLAYWRIGHT)

    def check_security_txt(self, url: str, http_response: Optional[str]) -> Dict[str, Any]:
        """
        Check for security.txt (RFC 9116)
        Returns: {found: bool, url: str, content_preview: str}
        """
        result = {
            "found": False,
            "url": f"{url}/.well-known/security.txt",
            "content_preview": ""
        }

        # This would require a dedicated HTTP request to /.well-known/security.txt
        # For now, we'll mark it as a placeholder that needs implementation
        # in the scanner's HTTP check phase

        return result

    def check_italian_requirements(self, html_body: str) -> Dict[str, Any]:
        """
        Check for Italian legal requirements:
        - P.IVA (VAT number)
        - Privacy Policy link
        """
        result = {
            "piva_found": False,
            "piva_value": None,
            "privacy_policy_found": False
        }

        # Check P.IVA
        piva_match = self.piva_pattern.search(html_body)
        if piva_match:
            result["piva_found"] = True
            result["piva_value"] = piva_match.group(1)

        # Check Privacy Policy (case insensitive)
        html_lower = html_body.lower()
        for keyword in self.privacy_keywords:
            if keyword in html_lower:
                result["privacy_policy_found"] = True
                break

        return result

    def check_cookie_banner(self, html_body: str) -> Dict[str, Any]:
        """
        Detect cookie consent banner presence
        """
        result = {
            "banner_detected": False,
            "matched_keywords": []
        }

        html_lower = html_body.lower()
        for keyword in self.cookie_keywords:
            if keyword in html_lower:
                result["banner_detected"] = True
                result["matched_keywords"].append(keyword)

        return result

    async def _check_with_playwright(
        self, url: str, pinned_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fallback: Use Playwright to render the page and check for compliance.

        SSRF: Chromium re-resolves the FQDN at navigation time, so without
        pinning a DNS rebind could send the render to an internal address. We
        require the API-validated `pinned_ip` and force Chromium to map the
        target host to it (``--host-resolver-rules``), and abort any sub-resource
        request to an internal host. If we cannot pin safely, we skip the
        dynamic check rather than navigate via uncontrolled DNS.
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed. Skipping dynamic check.")
            return {}

        host = urlparse(url).hostname or ""
        if not host or _is_blocked_host(host):
            logger.warning("Skipping Playwright dynamic check for unsafe host: %s", host)
            return {}
        if not pinned_ip or _is_blocked_host(pinned_ip):
            # No validated public IP to pin to — refuse to let Chromium resolve
            # the host itself (DNS-rebinding risk).
            logger.warning(
                "Skipping Playwright dynamic check for %s: no safe pinned IP", host
            )
            return {}

        logger.info(
            f"Starting Playwright dynamic check for {url} (pinned {host} -> {pinned_ip})"
        )
        # L5: serialize browser launches through the per-checker semaphore;
        # released in the finally below regardless of which path returns.
        await self._playwright_semaphore.acquire()
        try:
            async with async_playwright() as p:
                # We assume 'playwright install' has been run.
                try:
                    browser = await p.chromium.launch(
                        headless=True,
                        # Pin the target host to the validated IP for every port,
                        # so navigation cannot be rebinded to an internal address.
                        args=[f"--host-resolver-rules=MAP {host} {pinned_ip}"],
                    )
                except Exception as e:
                    logger.error(f"Failed to launch Playwright browser: {e}. Did you run 'playwright install'?")
                    return {}

                # New page; ignore HTTPS errors (the pinned host may serve an
                # IP-mismatched cert). Downloads are off by default.
                page = await browser.new_page(ignore_https_errors=True)

                # Defense in depth: abort any request to an internal host — e.g.
                # a malicious page embedding <img src="http://169.254.169.254/">,
                # which uses an IP literal and so bypasses host-resolver-rules.
                async def _guard(route):
                    try:
                        req_host = urlparse(route.request.url).hostname or ""
                        if _is_blocked_host(req_host):
                            await route.abort()
                        else:
                            await route.continue_()
                    except Exception:
                        await route.abort()

                await page.route("**/*", _guard)

                # Go to URL with timeout
                try:
                    # Wait for network idle to ensure JS has loaded
                    await page.goto(url, timeout=30000, wait_until="networkidle")
                except Exception as e:
                    logger.warning(f"Playwright navigation failed for {url}: {e}")
                    await browser.close()
                    return {}

                # Get rendered HTML
                content = await page.content()

                # Run checks on rendered content
                italian_compliance = self.check_italian_requirements(content)
                cookie_banner = self.check_cookie_banner(content)

                await browser.close()

                return {
                    "italian_compliance": italian_compliance,
                    "cookie_banner": cookie_banner,
                    "method": "dynamic_playwright"
                }
        except Exception as e:
            logger.error(f"Playwright check failed: {e}")
            return {}
        finally:
            self._playwright_semaphore.release()

    async def analyze_page(
        self, url: str, html_body: str, pinned_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run all legal checks on a page.
        Implements Multi-Fallback:
        1. Static Analysis (Fast)
        2. Dynamic Analysis (Slow, if needed)
        """
        # 1. Static Analysis
        static_italian = self.check_italian_requirements(html_body)
        static_cookie = self.check_cookie_banner(html_body)

        result = {
            "url": url,
            "italian_compliance": static_italian,
            "cookie_banner": static_cookie,
            "method": "static"
        }

        # 2. Check if we need fallback
        # We fallback if:
        # - P.IVA missing
        # - Privacy Policy missing
        # - Cookie Banner missing

        needs_fallback = False
        if not static_italian["piva_found"]:
            needs_fallback = True
        if not static_italian["privacy_policy_found"]:
            needs_fallback = True
        if not static_cookie["banner_detected"]:
            needs_fallback = True

        if needs_fallback and PLAYWRIGHT_AVAILABLE:
            logger.info(f"Static analysis insufficient for {url}. Attempting dynamic analysis.")
            dynamic_result = await self._check_with_playwright(url, pinned_ip=pinned_ip)

            if dynamic_result:
                # Merge results - prefer dynamic if found
                if dynamic_result.get("italian_compliance"):
                    # If dynamic found P.IVA and static didn't, take dynamic
                    if dynamic_result["italian_compliance"]["piva_found"]:
                        result["italian_compliance"]["piva_found"] = True
                        result["italian_compliance"]["piva_value"] = dynamic_result["italian_compliance"]["piva_value"]

                    # If dynamic found Privacy Policy
                    if dynamic_result["italian_compliance"]["privacy_policy_found"]:
                        result["italian_compliance"]["privacy_policy_found"] = True

                if dynamic_result.get("cookie_banner"):
                    if dynamic_result["cookie_banner"]["banner_detected"]:
                        result["cookie_banner"]["banner_detected"] = True
                        result["cookie_banner"]["matched_keywords"] = dynamic_result["cookie_banner"]["matched_keywords"]

                result["method"] = "hybrid"

        return result
