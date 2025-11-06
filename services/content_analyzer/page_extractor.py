import json
import math
import random
import time
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from io import BytesIO
import base64
import tempfile
from PIL import Image
import requests
from selenium import webdriver
from selenium.webdriver import ChromeOptions
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import WebDriverException, TimeoutException
from bs4 import BeautifulSoup, Comment

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/16.0 Safari/605.1.15",
]

DEFAULT_BLOCKLIST = [
    "*://www.google-analytics.com/*",
    "*://ssl.google-analytics.com/*",
    "*://www.googletagmanager.com/*",
    "*://googletagmanager.com/*",
    "*://www.facebook.com/*",
    "*://connect.facebook.net/*",
    "*://static.doubleclick.net/*",
    "*://ads*.google.com/*",
    "*://pagead2.googlesyndication.com/*",
    "*://www.googleadservices.com/*",
    "*://analytics.google.com/*",
    "*://cdn.segment.com/*",
    "*://static.hotjar.com/*",
    "*://script.hotjar.com/*",
    "*://browser-update.org/*"
]


class PageExtractor:

    def __init__(
        self,
        headless: bool = False,
        user_agent: Optional[str] = None,
        accept_language: str = "en-US,en;q=0.9",
        blocklist: Optional[List[str]] = None,
        page_load_timeout: int = 20,
        script_timeout: int = 10,
        implicit_wait: int = 3,
    ):
        self.headless = headless
        self.user_agent = user_agent or random.choice(DEFAULT_USER_AGENTS)
        self.accept_language = accept_language
        self.blocklist = blocklist or DEFAULT_BLOCKLIST
        self.page_load_timeout = page_load_timeout
        self.script_timeout = script_timeout
        self.implicit_wait = implicit_wait

        self.driver: Optional[webdriver.Chrome] = None


    def _make_driver(self) -> webdriver.Chrome:
        options = ChromeOptions()
        tmp_profile = tempfile.mkdtemp()
        options.add_argument(f"--user-data-dir={tmp_profile}")

        options.add_argument("--window-size=1366,768")

        if self.headless:
            options.add_argument("--headless=new")

        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_argument("--disable-gpu")

        caps = DesiredCapabilities.CHROME.copy()
        caps["goog:loggingPrefs"] = {"performance": "ALL"}

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(self.page_load_timeout)
        driver.set_script_timeout(self.script_timeout)
        driver.implicitly_wait(self.implicit_wait)

        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {
                    "source": """
// overwrite the `navigator` properties to make automation less detectable
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.navigator.chrome = { runtime: {} };
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
"""
                },
            )
        except Exception as e:
            logger.debug("CDP script injection failed: %s", e)

        try:
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": self.blocklist})
            headers = {"User-Agent": self.user_agent, "Accept-Language": self.accept_language}
            driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
        except Exception as e:
            logger.debug("CDP network setup failed: %s", e)

        return driver


    def _human_interaction_sim(self, driver: webdriver.Chrome):
        try:
            js = """
(function(){
  function move() {
    var evt = new MouseEvent('mousemove', {
      view: window, bubbles: true, cancelable: true,
      clientX: Math.floor(Math.random()*800 + 100),
      clientY: Math.floor(Math.random()*400 + 100)
    });
    document.dispatchEvent(evt);
  }
  move();
})();
"""
            driver.execute_script(js)
            time.sleep(random.uniform(0.2, 0.8))
        except Exception:
            pass


    def _extract_relevant(self, html: str, base_url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")

        visible_text = soup.get_text(separator=" ", strip=True)
        visible_text = visible_text[:200000]

        forms = []
        for f in soup.find_all("form"):
            inputs = []
            for i in f.find_all("input"):
                inputs.append({"name": i.get("name"), "type": (i.get("type") or "").lower(), "placeholder": i.get("placeholder")})
            forms.append({"action": f.get("action"), "method": (f.get("method") or "get").lower(), "inputs": inputs})

        inputs_all = soup.find_all("input")
        num_password = sum(1 for i in inputs_all if (i.get("type") or "").lower() == "password")

        anchors = soup.find_all("a", href=True)
        hrefs = [a["href"] for a in anchors]
        parsed_base = urlparse(base_url)
        base_host = parsed_base.hostname or ""
        external_hosts = set()
        for h in hrefs:
            try:
                p = urlparse(h)
                if p.hostname and p.hostname != base_host:
                    external_hosts.add(p.hostname)
            except Exception:
                continue

        scripts = soup.find_all("script")
        script_info = {
            "num_scripts": len(scripts),
            "external_scripts": [s.get("src") for s in scripts if s.get("src")],
            "inline_script_length_max": max((len((s.get_text() or "")) for s in scripts), default=0)
        }

        iframes = soup.find_all("iframe")
        meta_robots = soup.find("meta", {"name": "robots"})
        robots_noindex = False
        if meta_robots and meta_robots.get("content") and "noindex" in meta_robots.get("content").lower():
            robots_noindex = True

        features = {
            "page_length_chars": len(html),
            "visible_text_length": len(visible_text),
            "num_forms": len(forms),
            "num_inputs": len(inputs_all),
            "num_password_inputs": num_password,
            "num_links": len(hrefs),
            "num_external_domains": len(external_hosts),
            "external_domains_sample": list(external_hosts)[:6],
            "meta_robots_noindex": robots_noindex,
            "script_info": script_info,
            "num_iframes": len(iframes),
            "forms_sample": forms[:3],
        }

        return {"text": visible_text, "features": features}


    def _calc_compression_coef(self, width: int, height: int) -> float:
        total_pixels = width * height
        limit = 700_000

        if total_pixels > limit:
            coef = math.sqrt(limit / total_pixels)
        else:
            coef = 1.0

        return max(coef, 0.05)


    @staticmethod
    def image_to_base64(source: str | bytes, max_width: int = 400, max_height: int = 400) -> str:
        try:
            if isinstance(source, str):
                resp = requests.get(source, timeout=5)
                resp.raise_for_status()
                img = Image.open(BytesIO(resp.content))
            else:
                img = Image.open(BytesIO(source))

            img.thumbnail((max_width, max_height))
            buffered = BytesIO()
            img.save(buffered, format="JPEG", quality=70)
            b64_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
            logger.debug(f"Converted image to base64")
            return f"data:image/jpeg;base64,{b64_str}"
        except Exception as e:
            logger.debug(f"Failed to convert image to base64: {e}")
            return ""


    @staticmethod
    def clean_html_for_analysis(html: str) -> BeautifulSoup:
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup([
            "script", "style", "link", "meta", "noscript", "canvas", "video", "svg"
        ]):
            tag.decompose()

        for tag in soup.find_all("script", {"type": "application/json"}):
            tag.decompose()

        for comment in soup.find_all(string=lambda x: isinstance(x, Comment)):
            comment.extract()

        important_attrs = {"type", "name", "placeholder", "value", "href", "id", "class", "aria-label", "for", "role"}
        for tag in soup.find_all():
            tag.attrs = {k: v for k, v in tag.attrs.items() if k in important_attrs}

        return soup


    def fetch(self, url: str, timeout_after_load: int = 2) -> Dict[str, Any]:
        result: Dict[str, Any] = {"url": url, "status": "error", "error": None}
        try:
            self.driver = self._make_driver()
        except WebDriverException as e:
            result["error"] = f"webdriver_init_failed: {e}"
            return result

        driver = self.driver
        try:
            time.sleep(random.uniform(0.3, 1.0))
            driver.get(url)
            self._human_interaction_sim(driver)
            time.sleep(timeout_after_load)

            final_url = driver.current_url
            raw_html = driver.page_source
            cookies = driver.get_cookies()

            total_height = driver.execute_script("return document.body.scrollHeight")
            total_width = driver.execute_script("return document.body.scrollWidth")
            driver.set_window_size(total_width, total_height)
            time.sleep(0.3)
            png = driver.get_screenshot_as_png()
            img = Image.open(BytesIO(png))

            coef = self._calc_compression_coef(img.width, img.height)
            screenshot_bytes = base64.b64decode(base64.b64encode(png))
            screenshot_base64 = self.image_to_base64(
                screenshot_bytes,
                max_width=int(img.width * coef),
                max_height=int(img.height * coef)
            )

            # with open("base64_screenshot.txt", "w", encoding="utf-8") as f:
            #     f.write(screenshot_base64)

            raw_html = self.clean_html_for_analysis(raw_html).prettify()
            soup = BeautifulSoup(raw_html, "html.parser")
            visible_text = soup.get_text(separator=" ", strip=True)[:200000]

            extracted = self._extract_relevant(raw_html, final_url)

            result.update({
                "status": "ok",
                "final_url": final_url,
                "html": raw_html,
                "text": visible_text,
                "screenshot_base64": screenshot_base64,
                "features": extracted["features"],
                "cookies": cookies
            })
            return result

        except TimeoutException as e:
            result["error"] = f"timeout: {e}"
            return result
        except WebDriverException as e:
            result["error"] = f"webdriver_error: {e}"
            return result
        except Exception as e:
            result["error"] = f"general_error: {e}"
            return result
        finally:
            try:
                driver.quit()
            except Exception:
                pass
            self.driver = None


# Example usage:
if __name__ == "__main__":
    extractor = PageExtractor(headless=True)
    url_to_test = "https://nor11qtd.forms.app/untitled-form-2"
    # url_to_test = "https://btmailee.flazio.com/home?r=25915"
    url_to_test = "https://billblundell1.wixsite.com/my-site-2"
    data = extractor.fetch(url_to_test)
    print(json.dumps(data, indent=2))
