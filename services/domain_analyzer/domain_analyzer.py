import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import tldextract
import vt
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 7))

DOMAIN_RELEVANT_ENGINES = {
    "Abusix", "ADMINUSLabs", "Axur", "ChainPatrol", "CRDF", "Certego", "CINS Army",
    "Cluster25", "DNS8", "Netcraft", "OpenPhish", "Phishtank", "PhishLabs",
    "PhishFort", "URLhaus", "URLQuery", "SCUMWARE.org", "zvelo", "CyRadar",
    "EmergingThreats", "SafeToOpen", "Trustwave", "AlphaSOC", "MalwarePatrol"
}

class VirusTotalDomainClient:
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

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        ext = tldextract.extract(host)
        if not ext.domain:
            raise ValueError(f"Cannot extract domain from URL: {url}")
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    @staticmethod
    def _summarize_relevant_stats(relevant_results: List[Dict[str, Any]]) -> Dict[str, int]:
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

    def check_domain(self, url: str) -> Dict[str, Any]:
        try:
            domain = self._extract_domain(url)
        except ValueError as e:
            logger.error(str(e))
            return {"url": url, "error": str(e)}

        with vt.Client(self.api_key) as client:
            try:
                vt_domain = client.get_object(f"/domains/{domain}")
                all_results = vt_domain.last_analysis_results
            except vt.error.APIError as e:
                return {"url": url, "domain": domain, "error": f"VT API error: {str(e)}"}

            relevant_results = []
            for engine_name, result in all_results.items():
                if engine_name in DOMAIN_RELEVANT_ENGINES:
                    relevant_results.append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result")
                    })

            relevant_results.sort(
                key=lambda r: 0 if (r.get("category") == "malicious" or "phishing" in (r.get("result") or "").lower()) else 1
            )

            stats = self._summarize_relevant_stats(relevant_results)
            safe = stats["malicious"] == 0 and stats["suspicious"] == 0

            time_now = datetime.now(timezone.utc)
            time_exp = time_now + timedelta(days=EXPIRED_DAYS)
            return {
                "domain": domain,
                "safe": safe,
                "stats": stats,
                "details_url": f"https://www.virustotal.com/gui/domain/{domain}",
                "raw": {"analysis_results": relevant_results},
                "checked_at": time_now.isoformat(),
                "expire_time": time_exp.isoformat()
            }


if __name__ == "__main__":
    client = VirusTotalDomainClient()
    test_urls = [
        "https://nor11qtd.forms.app/untitled-form-2",
    ]
    for u in test_urls:
        result = client.check_domain(u)
        print("\n=== VirusTotal Domain Result ===")
        for k, v in result.items():
            print(f"{k}: {v}")
