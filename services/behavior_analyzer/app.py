import os
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from behavior_analyzer import BehavioralAnalyzer


if not os.getenv("BEHAVIOR_ANALYZER_PORT") or not os.getenv("BEHAVIOR_ANALYZER_HOST"):
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)


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

    return jsonify(best)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("BEHAVIOR_ANALYZER_PORT", 8004))
    host = os.getenv("BEHAVIOR_ANALYZER_HOST", "0.0.0.0")
    logger.info("Starting Behavior Analysis Service on %s:%s", host, port)
    app.run(host="0.0.0.0", port=8004)
