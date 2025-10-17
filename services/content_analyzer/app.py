import base64
import os
import logging
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from typing import Tuple
from google.genai import types

from page_extractor import PageExtractor

try:
    from google import genai
except Exception:
    genai = None


if not os.getenv("CONTENT_ANALYZER_PORT") or not os.getenv("CONTENT_ANALYZER_HOST"):
    dotenv_path = Path(__file__).parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 7))
GOOGLE_AI_API = os.getenv("GOOGLE_AI_API")
GOOGLE_AI_MODEL = os.getenv("GOOGLE_AI_MODEL", "gemini-2.5-flash-lite")
PAGE_FETCH_TIMEOUT = int(os.getenv("PAGE_FETCH_TIMEOUT", 2))

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


def build_prompt(full_html: str, original_url: str, final_url: str) -> str:
    prompt = f"""
You are a security content analyzer.
Analyze the following FULL HTML page content. You may also use the provided PAGE SCREENSHOT IMAGE as supplemental information.

Your task:
Detect possible phishing or impersonation attempts based on both textual and visual indicators.

Consider:
- visible text or language suggesting urgency, fear, or credential harvesting ("verify", "confirm", "update", "enter password", "secure your account", etc.);
- presence of input fields for passwords, credit cards, or personal identifiers (<input>, <form> actions);
- deceptive links that point to external or mismatched domains;
- fake login prompts, cloned UI layouts, or reused branding;
- visual indicators of impersonation or suspicious branding (logos, trademarks, layouts), if clearly visible in the screenshot;
- suspicious or mismatched branding (e.g., the HTML claims to be from PayPal, but the logo or color palette doesn't match).

Do NOT output any extra commentary, headings, or formatting.
Output STRICTLY in this exact format (plain text only):

1) True or False
2) Explanation in 2-5 sentences.

Rules:
- Line 1 must be exactly "1) True" or "1) False".
- Line 2 must start with "2) " followed by a short explanation (≤1000 characters).
- No markdown, no JSON, no extra lines, no self-reference.

Original page URL: {original_url}
Final URL: {final_url}
HTML:
{full_html}
"""
    return prompt.strip()


def parse_ai_response(text: str) -> Tuple[bool, str, str]:
    raw = text.strip()
    cleaned = re.sub(r"[*_#>`]+", "", raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    verdict = False
    explanation = ""

    if len(lines) >= 1:
        first = lines[0]
        if "true" in first.lower():
            verdict = True
        elif "false" in first.lower():
            verdict = False
        else:
            if "true" in cleaned.lower():
                verdict = True
            elif "false" in cleaned.lower():
                verdict = False

    m = re.split(r"1\)\s*(?:True|False)\s*2\)\s*", cleaned, flags=re.IGNORECASE)
    if len(m) >= 2 and m[1].strip():
        explanation = m[1].strip()
    elif len(lines) >= 2:
        explanation = lines[1]
    else:
        explanation = cleaned

    explanation = re.sub(r"(?i)^\s*(1\)|2\)|true|false|\*|\#|\-|\`)+", "", explanation).strip()
    explanation = re.sub(r"(?i)\b(1\)|2\))", "", explanation).strip()
    explanation = " ".join(explanation.split())[:1000].strip()

    raw_clean = re.sub(r"(?i)[\*\#\`]+", "", raw)
    raw_clean = re.sub(r"(?i)\b(1\)|2\))", "", raw_clean).strip()

    logger.debug("AI Response Parsed: verdict=%s, explanation=%s", verdict, explanation)

    return verdict, explanation, raw_clean


app = Flask(__name__)
extractor = PageExtractor(headless=True)


@app.route("/analyze_content", methods=["POST"])
def analyze_page():
    data = request.get_json(force=True)
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    logger.info("Received analyze request for: %s", url)
    fetched = extractor.fetch(url, timeout_after_load=PAGE_FETCH_TIMEOUT)

    if fetched.get("status") != "ok":
        logger.error("Page fetch failed: %s", fetched.get("error"))
        return jsonify({"url": url, "error": fetched.get("error")}), 500

    logger.info("Page fetched successfully: %s", url)
    html = fetched.get("html", "")
    final_url = fetched.get("final_url", url)
    screenshot_base64 = fetched.get("screenshot_base64", "")

    prompt = build_prompt(html, url, final_url)

    try:
        client = get_ai_client()
    except Exception as e:
        logger.exception("AI client init failed")
        return jsonify({"url": url, "error": f"AI client init failed: {e}"}), 500

    logger.info("Sending content to AI model for analysis: %s", GOOGLE_AI_MODEL)

    try:
        contents = [prompt]

        if screenshot_base64.startswith("data:image"):
            match = re.match(r"data:(image/\w+);base64,(.*)", screenshot_base64)
            if match:
                mime_type = match.group(1)
                encoded_data = match.group(2)
                image_bytes = base64.b64decode(encoded_data)
                image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
                contents.append(image_part)

        logger.info("AI content prepared, starting generation...")

        response_text = ""
        for chunk in client.models.generate_content_stream(
                model=GOOGLE_AI_MODEL,
                contents=contents
        ):
            if hasattr(chunk, "text") and chunk.text:
                response_text += chunk.text

        response = response_text

        ai_text = ""
        if hasattr(response, "text"):
            ai_text = response.text
        elif isinstance(response, dict) and "candidates" in response:
            cand = response["candidates"]
            if cand:
                ai_text = cand[0].get("content") or cand[0].get("text") or ""
        else:
            ai_text = str(response)
    except Exception as e:
        logger.exception("AI call failed")
        return jsonify({"url": url, "error": f"AI call failed: {e}"}), 500
    ai_end = datetime.now(timezone.utc)

    verdict_bool, explanation, raw_ai = parse_ai_response(ai_text)

    checked_at = ai_end.isoformat()
    expire_time = (ai_end + timedelta(days=EXPIRED_DAYS)).isoformat()

    result = {
        "verdict": verdict_bool,
        "explanation": explanation,
        "raw_ai": raw_ai,
        "checked_at": checked_at,
        "expire_time": expire_time
    }

    logger.info("Analysis finished for %s: verdict=%s", url, verdict_bool)
    return jsonify(result), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("CONTENT_ANALYZER_PORT", 8003))
    host = os.getenv("CONTENT_ANALYZER_HOST", "0.0.0.0")
    logger.info("Starting Page Analysis Service on %s:%s", host, port)
    app.run(host=host, port=port)
