import os
import logging
from pathlib import Path
from flask import Flask, request, jsonify
from typing import Dict, Any
from dotenv import load_dotenv
import requests

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

FAKE_DB: Dict[str, Dict[str, Any]] = {}


def merge_results(wr_result: Dict[str, Any], vt_result: Dict[str, Any]) -> Dict[str, Any]:
    safe = wr_result.get("safe", True) and vt_result.get("safe", True)
    stats = {
        "malicious": wr_result.get("stats", {}).get("malicious", 0) + vt_result.get("stats", {}).get("malicious", 0),
        "suspicious": wr_result.get("stats", {}).get("suspicious", 0) + vt_result.get("stats", {}).get("suspicious", 0),
        "harmless": wr_result.get("stats", {}).get("harmless", 0) + vt_result.get("stats", {}).get("harmless", 0),
        "undetected": wr_result.get("stats", {}).get("undetected", 0) + vt_result.get("stats", {}).get("undetected", 0),
    }
    threats = wr_result.get("threats", []) + vt_result.get("threats", [])
    details = {
        "webrisk": wr_result,
        "virustotal": vt_result
    }
    return {"url": wr_result.get("url"), "safe": safe, "stats": stats, "threats": threats, "details": details}


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        logger.warning("No URL provided in request")
        return jsonify({"error": "No URL provided"}), 400

    if url in FAKE_DB:
        logger.info(f"URL found in cache: {url}")
        return jsonify(FAKE_DB[url])

    logger.info(f"Checking URL: {url}")
    try:
        wr_result = webrisk.check_url(url)
        vt_result = virustotal.check_url(url)
        merged = merge_results(wr_result, vt_result)
        FAKE_DB[url] = merged
        logger.info(f"Check completed: {url} | Safe: {merged['safe']}")

        # add to history service
        history_service_host = os.getenv("HISTORY_APP_HOST", "history_service")  # ім'я сервісу
        history_service_port = int(os.getenv("HISTORY_APP_PORT", 8001))
        history_service_url = f"http://{history_service_host}:{history_service_port}/add_url"
        try:
            resp = requests.post(history_service_url, json={"url": url})
            if resp.status_code == 200:
                logger.info(f"URL added to history service: {url}")
            else:
                logger.error(f"Failed to add URL to history service: {resp.text}")
        except Exception as e:
            logger.error(f"Error connecting to history service: {e}")

        return jsonify(merged)

    except Exception as e:
        logger.error(f"Error checking URL {url}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/history", methods=["GET"])
def get_history():
    logger.info("Returning history")
    return jsonify(list(FAKE_DB.values()))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = "0.0.0.0"
    host = os.getenv("THREAT_INTEL_HOST", "0.0.0.0")
    logger.info(f"Starting Threat Intelligence Service on {host}:{port}")
    app.run(host=host, port=port)
