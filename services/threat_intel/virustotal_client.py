import logging
import os
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import List, Dict, Any, Optional
import vt
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PHISHING_RELEVANT_ENGINES = {
    "Artists Against 419",
    "ChainPatrol",
    "Chong Lua Dao",
    "desenmascara.me",
    "Google Safebrowsing",
    "Yandex Safebrowsing",
    "Netcraft",
    "OpenPhish",
    "Phishing Database",
    "Phishtank",
    "PhishFort",
    "PhishLabs",
    "SafeToOpen",
    "Spam404",
    "URLQuery",
    "alphaMountain.ai",
    "Axur",
    "ZeroFox",

    "Abusix",
    "Acronis",
    "BitDefender",
    "Dr.Web",
    "Emsisoft",
    "ESET",
    "ESTsecurity",
    "Forcepoint ThreatSeeker",
    "Fortinet",
    "G-Data",
    "Heimdal Security",
    "Kaspersky",
    "Quick Heal",
    "Rising",
    "Sangfor",
    "Sophos",
    "Trustwave",
    "Webroot",
    "Bkav",
    "Mimecast",
    "VIPRE",
    "Xcitium Verdict Cloud",
    "CyRadar",

    "malwares.com URL checker",
    "MalwarePatrol",
    "MalwareURL",
    "Malwared",
    "Quttera",
    "Sucuri SiteCheck",
    "Sansec eComscan",
    "URLhaus",
}


EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 7))


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None, dotenv_path: Optional[Path] = None):
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = os.getenv("VT_API_KEY")

            if not self.api_key:
                if dotenv_path is None:
                    dotenv_path = Path.cwd() / ".env"
                if dotenv_path.exists():
                    load_dotenv(dotenv_path=dotenv_path)
                    self.api_key = os.getenv("VT_API_KEY")

        if not self.api_key:
            raise ValueError("API key not found. Provide VT_API_KEY via env or pass api_key.")


    def _summarize_relevant_stats(self, relevant_results: List[Dict[str, Any]]) -> Dict[str, int]:
        summary = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0, "timeout": 0}
        for r in relevant_results:
            category = (r.get("category") or "").lower()
            result = (r.get("result") or "").lower()
            if "malicious" in category or "phishing" in result:
                summary["malicious"] += 1
            elif "suspicious" in category:
                summary["suspicious"] += 1
            elif "harmless" in category or "clean" in result:
                summary["harmless"] += 1
            elif "undetected" in category or not result:
                summary["undetected"] += 1
            else:
                summary["timeout"] += 1
        return summary


    def check_url(self, url: str) -> Dict[str, Any]:
        with vt.Client(self.api_key) as client:
            try:
                url_id = vt.url_id(url)
                vt_url = client.get_object(f"/urls/{url_id}")
                all_results = vt_url.last_analysis_results

            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    logger.info(f"URL not found in VT, submitting for scan: {url}")
                    analysis = client.scan_url(url, wait_for_completion=True)
                    vt_analysis = client.get_object(f"/analyses/{analysis.id}")

                    if not hasattr(vt_analysis, "results") or not vt_analysis.results:
                        return {"url": url, "error": "No analysis results found after scanning."}

                    all_results = vt_analysis.results
                    url_id = vt_analysis.id
                else:
                    return {"url": url, "error": f"VT API error: {str(e)}"}

            relevant_results = []
            for engine_name, result in all_results.items():
                if engine_name in PHISHING_RELEVANT_ENGINES:
                    relevant_results.append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result")
                    })

            relevant_results.sort(
                key=lambda r: (
                    0 if (r.get("category") == "malicious" or "phishing" in (r.get("result") or "").lower()) else 1
                )
            )

            stats = self._summarize_relevant_stats(relevant_results)
            safe = stats["malicious"] == 0 and stats["suspicious"] == 0

            time_now = datetime.now(UTC)
            time_exp = time_now + timedelta(days=EXPIRED_DAYS)
            return {
                "safe": safe,
                "stats": stats,
                "details_url": f"https://www.virustotal.com/gui/url/{url_id}",
                "raw": {"analysis_results": relevant_results},
                "checked_at": time_now.isoformat(),
                "expire_time": time_exp.isoformat()
            }


if __name__ == "__main__":
    client = VirusTotalClient()
    test_urls = [
        "https://nor11qtd.forms.app/untitled-form-2",
    ]
    for u in test_urls:
        result = client.check_url(u)
        print("\n=== VirusTotal result ===")
        for k, v in result.items():
            print(f"{k}: {v}")