import difflib
import os
import re
import json
import time
import math
import base64
import random
import logging
import tempfile
from io import BytesIO
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv
from PIL import Image
from bs4 import BeautifulSoup, Comment
from selenium import webdriver
from selenium.webdriver import ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from google.genai import types

try:
    from google import genai
except Exception:
    genai = None

import requests


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


if not os.getenv("GOOGLE_AI_API") or not os.getenv("GOOGLE_AI_MODEL"):
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)

GOOGLE_AI_API = os.getenv("GOOGLE_AI_API")
GOOGLE_AI_MODEL = os.getenv("GOOGLE_AI_MODEL", "gemini-2.5-flash-lite")
PAGE_LOAD_TIMEOUT = int(os.getenv("PAGE_FETCH_TIMEOUT", "15"))
SCRIPT_TIMEOUT = int(os.getenv("SCRIPT_TIMEOUT", "10"))
IMPLICIT_WAIT = int(os.getenv("IMPLICIT_WAIT", "3"))
THRESHOLD_DOM_CHANGE = float(os.getenv("THRESHOLD_DOM_CHANGE", "50.0"))

CONTENT_ANALYZER_CONTAINER_NAME = os.getenv("CONTENT_ANALYZER_CONTAINER_NAME", "content-analyzer")
CONTENT_ANALYZER_PORT = int(os.getenv("CONTENT_ANALYZER_PORT", 8003))
CONTENT_ANALYZER_URL = f"http://{CONTENT_ANALYZER_CONTAINER_NAME}:{CONTENT_ANALYZER_PORT}/analyze_content"

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]

if not GOOGLE_AI_API:
    logger.warning("GOOGLE_AI_API is not set. AI calls will fail if attempted.")

_ai_client = None


def get_ai_client():
    global _ai_client
    if _ai_client is None:
        if genai is None:
            raise RuntimeError("google.genai client library is not installed or importable.")
        _ai_client = genai.Client(api_key=GOOGLE_AI_API)
    return _ai_client


def _calc_compression_coef(width: int, height: int) -> float:
    total_pixels = width * height
    limit = 500_000
    return max(math.sqrt(limit / total_pixels) if total_pixels > limit else 1.0, 0.05)


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


def make_driver(headless=True, user_agent=None):
    options = ChromeOptions()

    profile_dir = "/tmp/chrome-profile"
    try:
        os.makedirs(profile_dir, exist_ok=True)
        os.chmod(profile_dir, 0o777)
        options.add_argument(f"--user-data-dir={profile_dir}")
    except Exception as e:
        logger.warning("Failed to create profile dir %s: %s", profile_dir, e)

    options.add_argument("--window-size=1366,768")
    if headless:
        options.add_argument("--headless=new")

    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-gpu")
    options.add_argument("--remote-debugging-port=9222")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    if user_agent:
        options.add_argument(f"--user-agent={user_agent}")

    options.add_argument("--enable-logging")
    options.add_argument("--v=1")

    service = Service(log_path="/tmp/chromedriver.log")

    driver = webdriver.Chrome(service=service, options=options)

    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    driver.set_script_timeout(SCRIPT_TIMEOUT)
    driver.implicitly_wait(IMPLICIT_WAIT)
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"},
        )
    except Exception:
        pass

    return driver


def human_like_movements(driver, iterations=3):
    try:
        for _ in range(iterations):
            x, y = random.randint(100, 900), random.randint(100, 700)
            driver.execute_script(f"""
                var ev = new MouseEvent('mousemove', {{bubbles:true, clientX:{x}, clientY:{y}}});
                document.dispatchEvent(ev);
            """)
            driver.execute_script(f"window.scrollBy(0, {random.randint(50, 300)});")
            time.sleep(random.uniform(0.3, 0.8))
    except Exception:
        pass


def get_full_dom(driver):
    import bs4

    def get_shadow_dom_script():
        return """
        function deepShadow(node) {
            let html = "";
            function traverse(n) {
                if (n.outerHTML) html += n.outerHTML;
                if (n.shadowRoot) {
                    html += "<shadow-root>";
                    Array.from(n.shadowRoot.children).forEach(traverse);
                    html += "</shadow-root>";
                }
                Array.from(n.children).forEach(traverse);
            }
            traverse(document.body);
            return html;
        }
        return deepShadow(document.body);
        """

    def extract_iframes():
        iframe_htmls = []
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        for iframe in iframes:
            try:
                driver.switch_to.frame(iframe)
                inner = driver.execute_script("return document.documentElement.outerHTML")
                iframe_htmls.append(inner)
                driver.switch_to.default_content()
            except Exception:
                continue
        return iframe_htmls

    try:
        dom = driver.execute_script(get_shadow_dom_script())
        dom = bs4.BeautifulSoup(dom, "html.parser").prettify()
        iframes = extract_iframes()
        return dom + "\n" + "\n".join(iframes)
    except Exception as e:
        print(f"Failed to get full DOM: {e}")
        return driver.page_source


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


def ask_model_for_actions(html: str, screenshot_b64: str) -> Dict[str, Any]:
    try:
        client = get_ai_client()

        prompt = """
You are simulating a naive human browsing a webpage.
From the provided HTML and screenshot, extract ONLY the user actions that are clearly visible **within the current viewport shown in the screenshot**.
Your task is to mimic what a real human would notice and interact with **at first glance**.

Extract the following:
- Clickable elements: buttons, links, checkboxes, radio buttons, form submission elements that are **fully visible in the screenshot** and appear as clearly interactable.
- Fillable fields: visible <input>, <textarea>, or other form elements **with a visible label, placeholder, or descriptive context**.

Return a JSON array like this:
[
  {"action": "click", "selector_text": "Submit", "selector": "button[type='submit']"},
  {"action": "fill", "field_label": "Email", "value": "john.doe@example.com", "selector": "input[name='email']"}
]

Strict instructions:

1. Use ONLY elements that are **clearly visible in the screenshot** and located **within the currently visible area**.
2. Include visible **checkboxes** and **radio buttons** where applicable.
3. Ignore hidden or collapsed content, modal windows, tabs, or sections not currently in the viewport.
4. For each action:
    - Include `selector` — a usable, specific CSS selector (e.g. by `id`, `name`, `placeholder`, `label[for]`, `aria-label`).
    - For `fill` — include:
        - `field_label`: label text, placeholder, or any visible context.
        - `value`: a realistic example value (e.g., name, email, card number).
4a. When selecting the `selector`:
    - Prefer using `id`, `name`, or `aria-label` attributes written in **ASCII / English characters**, if available.
    - Avoid using `placeholder` or `label` attributes containing special or non-ASCII characters like smart quotes, right single quotes, or Unicode apostrophes, unless no other selector exists.
    - If both `name='name'` and `placeholder='Імʼя'` are available — use `input[name='name']`.
5. Do NOT guess or include actions for elements that are not visible in the screenshot.
6. Use BOTH HTML structure and screenshot appearance to determine element visibility and intent.
7. Do NOT repeat actions for the same element.
8. Choose the `value` for each `fill` action according to the **language and context of the field label**
9. Always match the value language to the language of the label or placeholder. Do NOT mix languages in the same form.
10. Order matters: return the actions in the **natural sequence** that a real user would perform them:
    - First fill all visible fields in order from top to bottom
    - Then select checkboxes and radio buttons (if visible)
    - Only after that, perform any submit or navigation clicks (e.g., "Відправити", "Submit", "Continue")
    - Do NOT click on submission buttons before the form is filled or options selected

If there are **no visible user actions at all**, return an empty array: `[]`.

Examples of good `fill` values:
- Email: "example@example.com"
- Phone: "380991234567"
- Passport: "KB123456"
- Card Number: "4000123456789010"
- Expiry: "12/29"
- CVV: "123"

Output ONLY a JSON array. No explanations. No preamble.
"""

        contents = [prompt, html[:150000]]
        if screenshot_b64.startswith("data:image"):
            match = re.match(r"data:(image/\w+);base64,(.*)", screenshot_b64)
            if match:
                mime_type, encoded = match.groups()
                img_bytes = base64.b64decode(encoded)
                img_part = types.Part.from_bytes(data=img_bytes, mime_type=mime_type)
                contents.append(img_part)

        logger.info("Sending request to model %s for multi-action detection", GOOGLE_AI_MODEL)
        response_text = ""
        for chunk in client.models.generate_content_stream(
                model=GOOGLE_AI_MODEL,
                contents=contents
        ):
            if hasattr(chunk, "text") and chunk.text:
                response_text += chunk.text

        logger.info("Model response:\n %s\n----------------", response_text)
        response_text = response_text.strip()
        response_text = re.sub(r"```json|```", "", response_text).strip()
        response_text = re.sub(r"\\'", "'", response_text)

        try:
            actions = json.loads(response_text)
            if isinstance(actions, list):
                logger.info("Parsed actions: %d items", len(actions))
                if len(actions) == 0:
                    return {"status": "no_actions", "actions": []}
                else:
                    return {"status": "ok", "actions": actions}
            else:
                logger.warning("Model returned non-list JSON")
                return {"status": "error", "actions": [], "error": "Model output is not a list"}
        except Exception as e:
            logger.warning("JSON parse failed: %s | text: %s", e, response_text[:300])
            return {"status": "error", "actions": [], "error": f"JSON parse failed: {e}"}

    except Exception as e:
        logger.warning("ask_model_for_actions failed: %s", e)
        return {"status": "error", "actions": [], "error": str(e)}


def sanitize_filename(url: str) -> str:
    cleaned = re.sub(r"[^\w\-_.]", "_", url.replace("https://", "").replace("http://", ""))
    return cleaned[:150]


class BehavioralAnalyzer:
    def __init__(self, headless=True, user_agent=None):
        self.headless = headless
        self.user_agent = user_agent or random.choice(DEFAULT_USER_AGENTS)
        self.driver = None


    def _init_driver(self):
        self.driver = make_driver(self.headless, self.user_agent)


    def get_screenshot_base64(self) -> (str, bytes):
        driver = self.driver

        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(0.3)
        MAX_HEIGHT = 4000
        MAX_WIDTH = 2000
        total_height = driver.execute_script("return document.body.scrollHeight")
        total_width = driver.execute_script("return document.body.scrollWidth")
        driver.set_window_size(
            min(total_width, MAX_WIDTH),
            min(total_height, MAX_HEIGHT)
        )

        driver.execute_script("""
            document.body.style.overflow = 'hidden';
            document.body.style.position = 'relative';
        """)
        time.sleep(0.1)

        png = driver.get_screenshot_as_png()
        img = Image.open(BytesIO(png))

        coef = _calc_compression_coef(img.width, img.height)
        screenshot_bytes = base64.b64decode(base64.b64encode(png))

        screenshot_b64 = image_to_base64(
            screenshot_bytes,
            max_width=int(img.width * coef),
            max_height=int(img.height * coef)
        )

        return screenshot_b64, png


    @staticmethod
    def calculate_dom_diff(before: List[str], after: List[str]) -> float:
        matcher = difflib.SequenceMatcher(None, before, after)
        similarity = matcher.ratio()
        delta_percent = round((1 - similarity) * 100, 2)
        return delta_percent


    @staticmethod
    def ask_content_analyzer(html: str, original_url: str, screenshot_b64: Optional[str] = None) -> Dict[str, Any]:
        try:
            resp = requests.post(
                CONTENT_ANALYZER_URL,
                json={"html": html,
                      "original_url": original_url,
                      "screenshot_base64": screenshot_b64 or ""},
                timeout=50
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning("Content analyzer request failed: %s", e)
            return {}


    def perform_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for idx, action in enumerate(actions):
            try:
                selector = action.get("selector")
                if not selector:
                    logger.warning("No selector provided for action: %s", action)
                    continue

                if random.random() < 0.9:
                    human_like_movements(self.driver, iterations=random.randint(1, 3))

                url_before = self.driver.current_url
                dom_before = get_full_dom(self.driver).splitlines()
                window_handles_before = self.driver.window_handles

                if action["action"] == "fill":
                    value = action.get("value", "")
                    logger.info("Filling [%s] with value [%s]", selector, value)
                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    self.driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});",
                                               element)
                    element.clear()

                    for char in value:
                        element.send_keys(char)
                        time.sleep(random.uniform(0.05, 0.15))

                elif action["action"] == "click":
                    logger.info("Clicking on [%s]", selector)
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if not elements:
                        raise ValueError(f"Element not found: {selector}")
                    el = elements[0]

                    if not el.is_displayed():
                        parent_label = self.driver.execute_script("""
                            let input = arguments[0];
                            while (input && input.tagName !== 'LABEL') {
                                input = input.parentElement;
                            }
                            return input;
                        """, el)
                        if parent_label:
                            logger.info("Clicking parent label for hidden input.")
                            self.driver.execute_script("arguments[0].click();", parent_label)
                        else:
                            logger.warning("Element hidden and no label parent found.")
                    else:
                        self.driver.execute_script(
                            "arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", el)
                        el.click()

                time.sleep(random.uniform(0.8, 2.3))

                alert_text = None
                try:
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    logger.info("Alert detected: %s", alert_text)
                    alert.accept()
                    logger.info("Alert accepted.")
                except Exception:
                    pass

                url_after = self.driver.current_url
                if url_before != url_after:
                    time.sleep(5)
                    url_after = self.driver.current_url
                    logger.info("URL changed from %s to %s", url_before, url_after)

                delta, content_report = 0.0, {}
                if url_before == url_after:
                    dom_after = get_full_dom(self.driver)
                    delta = self.calculate_dom_diff(dom_before, dom_after.splitlines())
                    if delta > THRESHOLD_DOM_CHANGE:
                        logger.info("DOM changed by %.2f%% after action [%s]", delta, action["action"])
                        screen_b64, png_new = self.get_screenshot_base64()
                        # with open(f"action_{idx+1}_screenshot.png", "wb") as f:
                        #     f.write(png_new)
                        dom_after = clean_html_for_analysis(dom_after).prettify()
                        content_report = self.ask_content_analyzer(dom_after, self.driver.current_url, screen_b64)
                        logger.info("Content analyzer report: %s", content_report)

                window_handles_after = self.driver.window_handles
                new_window_opened = len(window_handles_after) > len(window_handles_before)
                new_handles = list(set(window_handles_after) - set(window_handles_before))
                new_window_urls = []
                for handle in new_handles:
                    self.driver.switch_to.window(handle)
                    new_window_urls.append(self.driver.current_url)
                self.driver.switch_to.window(window_handles_before[0])
                if new_window_opened:
                    logger.info("New window(s) opened with URLs: %s", new_window_urls)

                results.append({"action": action,

                                "redirect": url_before != url_after,
                                "url_before": url_before,
                                "url_after": url_after,

                                "dom_changed": delta > THRESHOLD_DOM_CHANGE,
                                "dom_change_percent": delta,
                                "content_report": content_report,

                                "new_window_opened": bool(new_window_opened),
                                "new_window_urls": new_window_urls,

                                "alert_present": alert_text is not None,
                                "alert_text": alert_text
                                })

                if url_before != url_after:
                    logger.info("Redirect detected, stopping further actions.")
                    break

            except Exception as e:
                logger.warning("Failed to perform action %s: %s", action, str(e).split("Stacktrace:")[0])

        return results


    def analyze(self, url: str, max_actions=20) -> Dict[str, Any]:
        try:
            self._init_driver()
            driver = self.driver
            driver.get(url)
            human_like_movements(driver)
            try:
                WebDriverWait(driver, 15).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                time.sleep(5)
            except Exception:
                time.sleep(5)

            filename = sanitize_filename(url)
            screenshot_b64, png = self.get_screenshot_base64()
            # save png
            # with open(f"screenshot_{filename}.png", "wb") as f:
            #     f.write(png)

            html = get_full_dom(driver)
            soup = BeautifulSoup(html, "html.parser")
            html = soup.prettify()
            # with open(f"page_{filename}.html", "w", encoding="utf-8") as f:
            #     f.write(html)

            html = clean_html_for_analysis(html).prettify()
            res = ask_model_for_actions(html, screenshot_b64)
            if res.get("status") == "no_actions":
                logger.info("No user actions detected on the page.")
                return {"status": "no_actions", "actions": []}
            elif res.get("status") != "ok":
                logger.error("Action detection failed: %s", res.get("error"))
                return {"status": "error", "error": res.get("error")}

            actions = res.get("actions", [])[:max_actions]
            results = self.perform_actions(actions)
            return {"status": "ok", "results": results}

        except Exception as e:
            logger.error("Behavioral analysis failed: %s", e)
            return {"status": "error", "error": str(e)}

        finally:
            if self.driver:
                try:
                    self.driver.quit()
                    logger.info("ChromeDriver closed successfully.")
                except Exception as e:
                    logger.warning("Failed to close ChromeDriver: %s", e)
                self.driver = None


if __name__ == "__main__":
    CONTENT_ANALYZER_CONTAINER_NAME = "localhost"
    CONTENT_ANALYZER_URL = f"http://{CONTENT_ANALYZER_CONTAINER_NAME}:{CONTENT_ANALYZER_PORT}/analyze_content"
    HEADLESS = False
    analyzer = BehavioralAnalyzer(headless=HEADLESS)
    test_url = "https://btmailee.flazio.com/home?r=25915"
    # test_url = "https://btinternetbills.framer.ai/?editSite"
    # test_url = "https://nm2rhgsu.forms.app/phishing-example-diploma"
    # test_url = "https://billblundell1.wixsite.com/my-site-2"
    analyzer.analyze(test_url)
    if not HEADLESS:
        input("Press Enter to exit...")
