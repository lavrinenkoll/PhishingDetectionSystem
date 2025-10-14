import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta, UTC

EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 7))

class WebRiskClient:
    BASE_URL = "https://webrisk.googleapis.com/v1/uris:search"

    def __init__(self, api_key: Optional[str] = None, dotenv_path: Optional[Path] = None):
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = os.getenv("WEBRISK_API_KEY")

            if not self.api_key:
                if dotenv_path is None:
                    dotenv_path = Path.cwd() / ".env"
                if dotenv_path.exists():
                    load_dotenv(dotenv_path=dotenv_path)
                    self.api_key = os.getenv("WEBRISK_API_KEY")

        if not self.api_key:
            raise ValueError("API key not found. Provide WEBRISK_API_KEY via env or pass api_key.")

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "webrisk-client/1.0"})

    def _call_api(self, uri: str, threat_types: List[str]) -> Dict[str, Any]:
        params = {
            "key": self.api_key,
            "threatTypes": ",".join(threat_types),
            "uri": uri
        }
        resp = self.session.get(self.BASE_URL, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def check_url(self, url: str, threat_types: Optional[List[str]] = None) -> Dict[str, Any]:
        if threat_types is None:
            threat_types = ["SOCIAL_ENGINEERING"]
        try:
            resp_json = self._call_api(url, threat_types)
            threat = resp_json.get("threat")
            safe = not bool(threat and threat.get("threatTypes"))

            threats = []
            if threat:
                for t in threat.get("threatTypes", []):
                    threats.append({"engine": "Google Web Risk", "type": t.lower(), "category": "malicious"})

            stats = {
                "malicious": len(threats),
                "suspicious": 0,
                "harmless": 0 if threats else 1,
                "undetected": 0,
            }

            time_now = datetime.now(UTC)
            time_exp = time_now + timedelta(days=EXPIRED_DAYS)
            result = {
                "safe": safe,
                "stats": stats,
                "details_url": None,
                "raw": resp_json,
                "checked_at": time_now.isoformat(),
                "expire_time": time_exp.isoformat(),
            }

        except Exception as e:
            result = {"url": url, "error": str(e)}

        return result


    def batch_check(self, urls: List[str], threat_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        for u in urls:
            results.append(self.check_url(u, threat_types=threat_types))
        return results


if __name__ == "__main__":
    client = WebRiskClient()
    test_urls = [
        "https://nor11qtd.forms.app/untitled-form-2",
        # "http://testsafebrowsing.appspot.com/s/phishing.html",
        # "http://example.com"
    ]
    results = client.batch_check(test_urls)

    for result in results:
        for k, v in result.items():
            print(f"{k}: {v}")

