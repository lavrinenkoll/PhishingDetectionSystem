import os
import json
import logging
import requests
from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin


if not os.getenv("THREAT_INTEL_CONTAINER_NAME") or not os.getenv("THREAT_INTEL_PORT"):
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)

NUM_REDIRECTS = int(os.getenv("NUM_REDIRECTS", 1))


app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


SERVICES = {
    "threat_intel": {
        "url": f"http://{os.getenv('THREAT_INTEL_CONTAINER_NAME')}:{os.getenv('THREAT_INTEL_PORT')}",
        "endpoint": "/check"
    },
    "domain_analyzer": {
        "url": f"http://{os.getenv('DOMAIN_ANALYZER_CONTAINER_NAME')}:{os.getenv('DOMAIN_ANALYZER_PORT')}",
        "endpoint": "/check_domain"
    },
    "content_analyzer": {
        "url": f"http://{os.getenv('CONTENT_ANALYZER_CONTAINER_NAME')}:{os.getenv('CONTENT_ANALYZER_PORT')}",
        "endpoint": "/analyze_content"
    },
    "behavior_analyzer": {
        "url": f"http://{os.getenv('BEHAVIOR_ANALYZER_CONTAINER_NAME')}:{os.getenv('BEHAVIOR_ANALYZER_PORT')}",
        "endpoint": "/get_behavior"
    },
    "behavior_summary": {
        "url": f"http://{os.getenv('BEHAVIOR_ANALYZER_CONTAINER_NAME')}:{os.getenv('BEHAVIOR_ANALYZER_PORT')}",
        "endpoint": "/get_summary"
    }
}

HISTORY = {
    "check": f"http://{os.getenv('HISTORY_CONTAINER_NAME')}:{os.getenv('HISTORY_SERVICE_PORT')}/check_history",
    "update": f"http://{os.getenv('HISTORY_CONTAINER_NAME')}:{os.getenv('HISTORY_SERVICE_PORT')}/update_history"
}


def resolve_final_url(url: str, max_steps: int = 5, timeout: int = 6) -> str:
    session = requests.Session()

    try:
        for _ in range(max_steps):
            resp = session.get(
                url,
                allow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            if "Location" not in resp.headers:
                return url

            url = urljoin(url, resp.headers["Location"])

        return url
    except Exception:
        return url


def call_service(name: str, payload: dict) -> dict:
    service = SERVICES[name]
    url = service["url"] + service["endpoint"]

    # 1) history check
    try:
        history_resp = requests.post(
            HISTORY["check"],
            json={"service": name, "url": payload["url"]},
            timeout=5
        ).json()
    except Exception:
        history_resp = {"cached": False}
        logger.warning(f"[{name}] history check failed")

    if history_resp.get("cached"):
        return {"service": name, "cached": True, "data": history_resp["result"]}

    # 2) real call
    try:
        resp = requests.post(url, json=payload, timeout=120 if name == "behavior_analyzer" else 45).json()
        result = {"service": name, "cached": False, "data": resp}
    except Exception as e:
        result = {"service": name, "cached": False, "error": str(e)}

    # 3) history update
    try:
        requests.post(
            HISTORY["update"],
            json={"service": name, "url": payload["url"], "result": result},
            timeout=5
        )
    except Exception:
        logger.warning(f"[{name}] history update failed")

    return result


def extract_redirects(behavior_data: dict) -> list:
    redirects = set()
    if not isinstance(behavior_data, dict):
        return []
    for step in behavior_data.get("results", []):
        if step.get("redirect") and step.get("url_after"):
            redirects.add(step["url_after"])
        for w in step.get("new_window_urls", []):
            if w:
                redirects.add(w)
    return list(redirects)


def analyze_url_all_services(url: str, depth: int, source: str | None, stream_partial: bool):
    url = resolve_final_url(url)
    payload = {"url": url}
    full_results = {}
    enriched_list = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(call_service, name, payload): name for name in ("threat_intel", "domain_analyzer", "content_analyzer", "behavior_analyzer")}
        for future in as_completed(futures):
            res = future.result()

            res_with_meta = {
                **res,
                "url": url,
                "depth": depth,
                "source": source
            }
            full_results[res["service"]] = res_with_meta
            enriched_list.append(res_with_meta)

            if stream_partial:
                yield ("partial", res_with_meta)

    behavior = full_results.get("behavior_analyzer", {}).get("data", {})
    behavior_redirects = extract_redirects(behavior)

    yield ("complete", full_results, behavior_redirects, enriched_list)


def bfs_with_depth(origin_url: str):
    visited = set()
    redirects_chain = []
    accumulated_children = []
    root_behavior = []

    current_level = [(origin_url, 0, None)]
    while current_level:
        next_level = []
        for url, depth, source in current_level:
            if url in visited:
                continue
            visited.add(url)

            stream_partial = (depth == 0)

            last_complete = None
            for item in analyze_url_all_services(url, depth, source, stream_partial):
                if item[0] == "partial":
                    yield f"data: {json.dumps(item[1], ensure_ascii=False)}\n\n"
                else:
                    _, full_results, behavior_redirects, enriched_list = item
                    last_complete = (full_results, behavior_redirects, enriched_list)

            if not last_complete:
                continue

            full_results, behavior_redirects, enriched_list = last_complete

            if depth == 0:
                root_behavior = enriched_list
            else:
                accumulated_children.extend(enriched_list)

            if behavior_redirects:
                redirects_chain.append({
                    "source": url,
                    "depth": depth,
                    "children": behavior_redirects
                })

                if depth < NUM_REDIRECTS:
                    for child in behavior_redirects:
                        if child not in visited:
                            next_level.append((child, depth + 1, url))

        current_level = next_level

    summary_payload = {
        "origin": origin_url,
        "redirect_chain": redirects_chain,
        "analyzed_root": root_behavior,
        "analyzed_children": accumulated_children,
        "depth_limit": NUM_REDIRECTS
    }

    summary_result = call_service(
        "behavior_summary",
        {"url": origin_url, "summary_payload": summary_payload}
    )

    summary = summary_result.get("data", summary_result)
    cached = summary_result.get("cached", False)

    final_event = {
        "service": "behavior_summary",
        "cached": cached,
        "url": origin_url,
        "depth": 0,
        "source": None,
        "data": summary
    }
    yield f"data: {json.dumps(final_event, ensure_ascii=False)}\n\n"


@app.route("/check", methods=["POST"])
def check():
    input_data = request.get_json(force=True)
    if not input_data or "url" not in input_data:
        return jsonify({"error": "Expected JSON: {\"url\": \"https://example.com\"}"}), 400

    origin_url = input_data["url"]
    return Response(bfs_with_depth(origin_url), mimetype="text/event-stream")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    RISK_AGGREGATOR_PORT = int(os.getenv("RISK_AGGREGATOR_PORT", 8000))
    RISK_AGGREGATOR_HOST = os.getenv("RISK_AGGREGATOR_HOST", "0.0.0.0")
    app.run(host=RISK_AGGREGATOR_HOST, port=RISK_AGGREGATOR_PORT)
