import os
import json
import logging
import requests
from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlunparse
import re
import idna


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

WEIGHTS = {
    "threat_intel": float(os.getenv("THREAT_INTEL_WEIGHT", 0.15)),
    "domain_analyzer": float(os.getenv("DOMAIN_ANALYZER_WEIGHT", 0.15)),
    "content_analyzer": float(os.getenv("CONTENT_ANALYZER_WEIGHT", 0.3)),
    "behavior_analyzer": float(os.getenv("BEHAVIOR_ANALYZER_WEIGHT", 0.4)),
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
        resp = requests.post(url, json=payload, timeout=240 if name == "behavior_analyzer" else 70).json()
        result = {"service": name, "cached": False, "data": resp}
    except Exception as e:
        result = {"service": name, "cached": False, "data": {"error": f"Service call failed: {e}"}}

    # 3) history update
    error = result.get("data", {}).get("error", None)
    if not error:
        try:
            requests.post(
                HISTORY["update"],
                json={"service": name, "url": payload["url"], "result": result},
                timeout=5
            )
        except Exception:
            logger.warning(f"[{name}] history update failed")
    else:
        logger.error(f"[{name}] service call failed: {error}")
        result = {"service": name, "cached": False, "data": {"error": error}}

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


def normalize_url(url: str) -> str:
    if not url:
        return url

    url = url.strip()

    url = re.sub(r"\s+", "", url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    parsed = urlparse(url)
    scheme = "https" if parsed.scheme.lower() in ["http", "https"] else parsed.scheme
    netloc = parsed.netloc.lower()

    if netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path or ""
    if path != "/":
        path = path.rstrip("/")

    normalized = urlunparse((
        scheme,
        netloc,
        path if path else "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return normalized


def is_valid_unicode_domain(domain: str) -> bool:
    domain = domain.strip().rstrip(".")

    if not domain:
        return False

    if "." not in domain:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        try:
            idna.encode(label)
        except idna.IDNAError:
            return False

    tld = labels[-1]

    if len(tld) < 2:
        return False

    if not any(c.isalpha() for c in tld):
        return False

    return True


@app.route("/check", methods=["POST"])
def check():
    input_data = request.get_json(force=True)
    if not input_data or "url" not in input_data:
        return jsonify({"error": "Expected JSON: {\"url\": \"https://example.com\"}"}), 400

    origin_url = normalize_url(input_data["url"])

    parsed = urlparse(origin_url)
    host = parsed.netloc

    if not is_valid_unicode_domain(host):
        return jsonify({"error": "Invalid URL provided"}), 400

    return Response(bfs_with_depth(origin_url), mimetype="text/event-stream")


@app.route("/score", methods=["POST"])
def score():
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    values = payload.get("values") or {}
    if not isinstance(values, dict) or not values:
        return jsonify({"error": "Expected JSON with 'values' object"}), 400

    weight_by_service = {
        "threat_intel": WEIGHTS.get("threat_intel"),
        "domain_analyzer": WEIGHTS.get("domain_analyzer"),
        "content_analyzer": WEIGHTS.get("content_analyzer"),
        "behavior_summary": WEIGHTS.get("behavior_analyzer"),
    }

    component_scores = []

    if "threat_intel" in values:
        ti = values["threat_intel"] or {}
        vt_stats = ti.get("vt_stats") or {}
        webrisk_safe = ti.get("webrisk_safe", None)

        harmless = int(vt_stats.get("harmless", 0))
        suspicious = int(vt_stats.get("suspicious", 0))
        malicious = int(vt_stats.get("malicious", 0))
        undetected = int(vt_stats.get("undetected", 0))
        total = harmless + suspicious + malicious + undetected

        vt_risk = None
        if total > 0:
            vt_risk = (suspicious + malicious) / float(total)

        wr_risk = None
        if webrisk_safe is True:
            wr_risk = 0.0
        elif webrisk_safe is False:
            wr_risk = 1.0

        ti_risk = None
        if vt_risk is not None and wr_risk is not None:
            ti_risk = 0.5 * vt_risk + 0.5 * wr_risk
        elif vt_risk is not None:
            ti_risk = vt_risk
        elif wr_risk is not None:
            ti_risk = wr_risk

        if ti_risk is not None:
            w = weight_by_service["threat_intel"]
            component_scores.append((
                "Перевірка в базах загроз",
                max(0.0, min(1.0, ti_risk)),
                w,
                f"VirusTotal: {suspicious + malicious}/{max(total, 1)} підозрілі/всі; "
                f"WebRisk: {'безпечний' if webrisk_safe else 'небезпечний' if webrisk_safe is False else 'немає даних'}."
            ))

    if "domain_analyzer" in values:
        da = values["domain_analyzer"] or {}
        stats = da.get("vt_domain_stats") or {}
        harmless = int(stats.get("harmless", 0))
        suspicious = int(stats.get("suspicious", 0))
        malicious = int(stats.get("malicious", 0))
        undetected = int(stats.get("undetected", 0))
        total = harmless + suspicious + malicious + undetected

        if total > 0:
            risk = (suspicious + malicious) / float(total)
            w = weight_by_service["domain_analyzer"]
            component_scores.append((
                "Доменна перевірка",
                risk,
                w,
                f"Доменний аналіз: {suspicious + malicious}/{total} підозрілі/всі."
            ))

    if "content_analyzer" in values:
        ca = values["content_analyzer"] or {}
        verdict = ca.get("verdict", None)
        if isinstance(verdict, bool):
            risk = 1.0 if verdict else 0.0
            w = weight_by_service["content_analyzer"]
            component_scores.append((
                "Перевірка контенту",
                risk,
                w,
                f"Контент: {'фішингові ознаки виявлено' if verdict else 'ознаки фішингу не виявлено'}."
            ))

    if "behavior_summary" in values:
        ba = values["behavior_summary"] or {}
        verdict = ba.get("verdict", None)
        if isinstance(verdict, bool):
            risk = 1.0 if verdict else 0.0
            w = weight_by_service["behavior_summary"]
            component_scores.append((
                "Аналіз поведінки",
                risk,
                w,
                f"Поведінка: {'висока ймовірність фішингу' if verdict else 'не виявлено ризикової активності'}."
            ))

    valid_total_weight = sum(w for _, _, w, _ in component_scores)

    if valid_total_weight == 0:
        return jsonify({
            "integro_score": "N/A",
            "explanation": "Недостатньо даних.",
            "formula": "N/A"
        }), 200


    weighted_sum = 0.0
    formula_parts_raw = []
    normalized_parts = []

    for svc_name, risk, weight, _ in component_scores:
        w_norm = weight / valid_total_weight
        weighted_sum += risk * w_norm

        formula_parts_raw.append(f"{weight:.2f}·{risk:.2f}")
        normalized_parts.append(f"{w_norm:.2f}·{risk:.2f}")

    final_score = round(weighted_sum * 100, 1)

    formula = (
        " + ".join(normalized_parts)
        + f" = {weighted_sum:.4f} → {final_score}"
    )

    parts = []
    for svc_name, risk, weight, text in component_scores:
        perc = int(risk * 100)
        wperc = int(100 * (weight / valid_total_weight))
        parts.append(
            f"- {svc_name}: ризик {perc}%, внесок у підсумок {wperc}% → {text}"
        )

    explanation = (
        f"Оцінка = {final_score} із 100.\n"
        "Чим вище значення — тим більший сумарний ризик.\n\n"
        + "\n".join(parts)
    )

    return jsonify({
        "integro_score": final_score,
        "explanation": explanation,
        "formula": formula
    }), 200



@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    RISK_AGGREGATOR_PORT = int(os.getenv("RISK_AGGREGATOR_PORT", 8000))
    RISK_AGGREGATOR_HOST = os.getenv("RISK_AGGREGATOR_HOST", "0.0.0.0")
    app.run(host=RISK_AGGREGATOR_HOST, port=RISK_AGGREGATOR_PORT)
