import os
import logging
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv

from domain_analyzer import VirusTotalDomainClient


if not os.getenv("DOMAIN_ANALYZER_PORT") or not os.getenv("DOMAIN_ANALYZER_HOST"):
    dotenv_path = Path(__file__).parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

vt_domain_client = VirusTotalDomainClient()

app = Flask(__name__)


@app.route("/check_domain", methods=["POST"])
def check_domain():
    data = request.get_json()
    url = data.get("url")
    if not url:
        logger.warning("No URL provided in request")
        return jsonify({"error": "No URL provided"}), 400

    logger.info(f"Checking domain from URL: {url}")
    try:
        vt_result = vt_domain_client.check_domain(url)

        logger.info(f"Check completed: {url} | Safe: {vt_result.get('safe', True)}")
        last_checked_at = vt_result.get("last_checked_at", None)
        expire_time = vt_result.get("expire_time", None)
        return jsonify({
            "url": url,
            "virustotal_domain": vt_result,
            "last_checked_at": last_checked_at,
            "expire_time": expire_time,
            "safe": vt_result.get("safe", True)
        })

    except Exception as e:
        logger.error(f"Error checking domain {url}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("DOMAIN_ANALYZER_PORT", 8002))
    host = os.getenv("DOMAIN_ANALYZER_HOST", "0.0.0.0")
    logger.info(f"Starting Domain Analyzer Service on {host}:{port}")
    app.run(host=host, port=port)
