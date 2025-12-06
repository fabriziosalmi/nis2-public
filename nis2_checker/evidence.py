from playwright.sync_api import sync_playwright
import os
import logging

logger = logging.getLogger(__name__)

class EvidenceCollector:
    def __init__(self, output_dir="screenshots"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def take_screenshot(self, url: str, name: str) -> str:
        """Take a screenshot of the target URL."""
        if not url:
            return None
            
        filename = f"{name.replace(' ', '_').replace(':', '')}.png"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=30000)
                page.screenshot(path=filepath, full_page=False)
                browser.close()
            return filepath
        except Exception as e:
            logger.error(f"Failed to take screenshot of {url}: {e}")
            return None
