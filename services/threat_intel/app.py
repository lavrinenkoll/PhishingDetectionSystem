import os
import logging
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv

from webrisk_client import WebRiskClient
from virustotal_client import VirusTotalClient


if not os.getenv("THREAT_INTEL_PORT") or not os.getenv("THREAT_INTEL_HOST"):
    dotenv_path = Path(__file__).parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

webrisk = WebRiskClient()
virustotal = VirusTotalClient()

app = Flask(__name__)


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        logger.warning("No URL provided in request")
        return jsonify({"error": "No URL provided"}), 400

    logger.info(f"Checking URL: {url}")
    try:
        wr_result = webrisk.check_url(url)
        vt_result = virustotal.check_url(url)

        safe = wr_result.get("safe", True) and vt_result.get("safe", True)
        logger.info(f"Check completed: {url} | Safe: {safe}")

        return jsonify({
            "url": url,
            "webrisk": wr_result,
            "virustotal": vt_result
        })

    except Exception as e:
        logger.error(f"Error checking URL {url}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("THREAT_INTEL_PORT", 8000))
    host = os.getenv("THREAT_INTEL_HOST", "0.0.0.0")
    logger.info(f"Starting Threat Intelligence Service on {host}:{port}")
    app.run(host=host, port=port)
