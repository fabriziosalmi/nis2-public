"""
Regional and Legal Compliance Checks
Validates security.txt, Italian P.IVA, Privacy Policy, Cookie Banners
"""
import re
import logging
from typing import Optional, Dict, Any

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("nis2scan")

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

    async def _check_with_playwright(self, url: str) -> Dict[str, Any]:
        """
        Fallback: Use Playwright to render the page and check for compliance.
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed. Skipping dynamic check.")
            return {}

        logger.info(f"Starting Playwright dynamic check for {url}")
        try:
            async with async_playwright() as p:
                # Launch browser (chromium is usually fine)
                # We assume 'playwright install' has been run
                try:
                    browser = await p.chromium.launch(headless=True)
                except Exception as e:
                    logger.error(f"Failed to launch Playwright browser: {e}. Did you run 'playwright install'?")
                    return {}

                # Create a new page and ignore HTTPS errors (common when scanning IPs or internal sites)
                page = await browser.new_page(ignore_https_errors=True)
                
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
    
    async def analyze_page(self, url: str, html_body: str) -> Dict[str, Any]:
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
            dynamic_result = await self._check_with_playwright(url)
            
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
