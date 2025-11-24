import json
import os
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from behavior_analyzer import BehavioralAnalyzer
from datetime import datetime, timedelta, timezone

try:
    from google import genai
except Exception:
    genai = None


if not os.getenv("BEHAVIOR_ANALYZER_PORT") or not os.getenv("BEHAVIOR_ANALYZER_HOST"):
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)

_ai_client = None
def get_ai_client():
    global _ai_client
    if _ai_client is None:
        if genai is None:
            raise RuntimeError("google.genai not installed")
        _ai_client = genai.Client(api_key=GOOGLE_AI_API)
    return _ai_client

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", 3))
HEADLESS = os.getenv("HEADLESS", "true").lower() == "true"
EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 7))
GOOGLE_AI_API = os.getenv("GOOGLE_AI_API")
GOOGLE_AI_MODEL = os.getenv("GOOGLE_AI_MODEL", "gemini-2.5-flash-lite")


@app.route("/get_behavior", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    url = data.get("url")
    retries = data.get("retries", MAX_ATTEMPTS)

    if not url:
        return jsonify({"error": "Missing 'url'"}), 400

    logger.info("Starting behavioral analysis for: %s", url)
    results = []

    for attempt in range(retries):
        logger.info("Attempt %d of %d", attempt + 1, retries)
        analyzer = BehavioralAnalyzer(headless=HEADLESS)
        try:
            result = analyzer.analyze(url)
            results.append(result)
        except Exception as e:
            logger.warning("Attempt %d failed: %s", attempt + 1, e)

    def score(r):
        if r["status"] != "ok":
            return -1
        return sum([
            len(r.get("results", [])),
            sum(1 for a in r.get("results", []) if a.get("dom_changed")),
            sum(1 for a in r.get("results", []) if a.get("new_window_opened")),
        ])

    best = max(results, key=score, default=None)

    if not best:
        return jsonify({"status": "error", "error": "All attempts failed."}), 500

    # add checked_at and expire_time
    now = datetime.now(timezone.utc)
    best["checked_at"] = now.isoformat()
    best["expire_time"] = (now + timedelta(days=EXPIRED_DAYS)).isoformat()

    return jsonify(best)


def build_prompt(summary_payload: dict) -> str:
    origin = summary_payload.get("origin", "unknown origin")

    redirect_lines = []
    for step in summary_payload.get("redirect_chain", []):
        src = step.get("source")
        depth = step.get("depth")
        for child in step.get("children", []):
            redirect_lines.append(f"[depth={depth}] {src} → {child}")
    redirect_text = "\n".join(redirect_lines) if redirect_lines else "No redirects observed."

    def integrate(entries, url_map, is_root=False):
        for entry in entries:
            url = entry.get("url")
            service = entry.get("service")
            data = entry.get("data", {})

            url_map.setdefault(url, {
                "type": "root" if is_root else "child",
                "domain": None,
                "content": None,
                "threat": None,
                "behavior": []
            })

            if service == "domain_analyzer":
                vtd = data.get("virustotal_domain", {})
                url_map[url]["domain"] = {
                    "domain": vtd.get("domain"),
                    "safe": vtd.get("safe"),
                    "malicious": vtd.get("stats", {}).get("malicious", 0),
                    "undetected": vtd.get("stats", {}).get("undetected", 0)
                }

            elif service == "content_analyzer":
                url_map[url]["content"] = {
                    "verdict": data.get("verdict"),
                    "explanation": data.get("explanation", "").strip()
                }

            elif service == "threat_intel":
                vt = data.get("virustotal", {})
                url_map[url]["threat"] = {
                    "safe": vt.get("safe"),
                    "malicious": vt.get("stats", {}).get("malicious", 0),
                    "harmless": vt.get("stats", {}).get("harmless", 0)
                }

            elif service == "behavior_analyzer":
                for act in data.get("results", []):
                    url_map[url]["behavior"].append({
                        "action": act["action"].get("action"),
                        "field": act["action"].get("field_label") or act["action"].get("selector"),
                        "value_filled": act["action"].get("value"),
                        "redirect": act.get("redirect"),
                        "new_window": act.get("new_window_opened"),
                        "url_before": act.get("url_before"),
                        "url_after": act.get("url_after"),
                    })

    url_map = {}
    integrate(summary_payload.get("analyzed_root", []), url_map, is_root=True)
    integrate(summary_payload.get("analyzed_children", []), url_map, is_root=False)

    timeline = []
    for url, info in url_map.items():
        role = "ROOT (initial page)" if info["type"] == "root" else "CHILD (redirect/new-window)"
        section = f"URL: {url}\n  Role: {role}"

        if info["domain"]:
            d = info["domain"]
            section += f"\n  Domain reputation: {d['domain']} → safe={d['safe']} (malicious={d['malicious']}, undetected={d['undetected']})"

        if info["threat"]:
            t = info["threat"]
            section += f"\n  Threat intel: malicious={t['malicious']}, harmless={t['harmless']}, safe={t['safe']}"

        if info["content"]:
            c = info["content"]
            section += f"\n  Content evaluation: {'PHISHING' if c['verdict'] else 'LEGIT'} — {c['explanation']}"

        if info["behavior"]:
            section += "\n  User interaction trace:"
            for b in info["behavior"]:
                section += f"\n    - Performed action: {b['action']} on '{b['field']}'" \
                           f"{' (value=' + b['value_filled'] + ')' if b['value_filled'] else ''}" \
                           f" → redirect={b['redirect']}, new_window={b['new_window']}" \
                           f"\n      URL before: {b['url_before']}" \
                           f"\n      URL after: {b['url_after']}"

        timeline.append(section)

    timeline_text = "\n\n".join(timeline)

    prompt = f"""
    You are a professional cybersecurity analyst specializing in phishing detection, credential harvesting analysis, and behavioral threat forensics.

    Carefully analyze the entire chain of interaction, not only single-page indicators.
    Pay specific attention to:
    - Whether the user is guided toward entering login credentials
    - How redirections change the domain trust profile over time
    - Whether behavior resembles impersonation of a known service
    - Whether redirects lead to legitimate authentication or mimicry / spoofing
    - How content, domain reputation, and UI interactions reinforce each other

    Start URL (initial user entry point):
    {origin}

    Observed redirection chain (chronological):
    {redirect_text}

    Cross-service evaluation and reconstructed user interaction timeline:
    {timeline_text}

    Based on this, decide whether the overall flow represents a coordinated phishing attempt aimed at credential theft, brand impersonation, or user deception. Your reasoning should be reflected in a clear, coherent explanation.
    """.strip()

    return prompt


@app.route("/get_summary", methods=["POST"])
def behavior_summary():
    data = request.get_json(force=True)
    summary_payload = data.get("summary_payload")

    if not summary_payload:
        return jsonify({"error": "missing summary_payload"}), 400

    prompt = build_prompt(summary_payload)

    try:
        client = get_ai_client()
        phishing_schema = {
            "type": "object",
            "properties": {
                "is_phishing": {
                    "type": "boolean",
                    "description": "True if this is phishing / credential theft flow, otherwise False."
                },
                "explanation": {
                    "type": "string",
                    "description": "Detailed explanation (4–10 sentences) using concrete evidence from the timeline."
                }
            },
            "required": ["is_phishing", "explanation"],
            "additionalProperties": False,
        }

        response = client.models.generate_content(
            model=GOOGLE_AI_MODEL,
            contents=prompt,
            config={
                "temperature": 0.1,
                "top_p": 0.9,
                "max_output_tokens": 1500,
                "seed": 0,
                "response_mime_type": "application/json",
                "response_json_schema": phishing_schema,
            },
        )

        data = json.loads(response.text)

        verdict = bool(data.get("is_phishing", False))
        explanation = str(data.get("explanation", "")).strip()
        now = datetime.now(timezone.utc)

        return jsonify({
            "verdict": verdict,
            "explanation": explanation,
            "raw_ai": response.text,
            "checked_at": now.isoformat(),
            "expire_time": (now + timedelta(days=EXPIRED_DAYS)).isoformat(),
            "summary_payload": summary_payload
        })

    except Exception as e:
        logger.exception("AI call failed")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("BEHAVIOR_ANALYZER_PORT", 8004))
    host = os.getenv("BEHAVIOR_ANALYZER_HOST", "0.0.0.0")
    logger.info("Starting Behavior Analysis Service on %s:%s", host, port)
    app.run(host="0.0.0.0", port=8004)
