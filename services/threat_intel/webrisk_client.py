import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from dotenv import load_dotenv


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
        resp_json = self._call_api(url, threat_types)
        threat = resp_json.get("threat")
        safe = not bool(threat and threat.get("threatTypes"))
        return {"url": url, "safe": safe, "threat": threat, "raw": resp_json}


    def batch_check(self, urls: List[str], threat_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        for u in urls:
            try:
                results.append(self.check_url(u, threat_types=threat_types))
            except Exception as e:
                results.append({"url": u, "error": str(e)})
        return results


if __name__ == "__main__":
    client = WebRiskClient()
    test_urls = [
        "http://testsafebrowsing.appspot.com/s/phishing.html",
        "http://example.com"
    ]
    results = client.batch_check(test_urls)
    for result in results:
        print(result)
