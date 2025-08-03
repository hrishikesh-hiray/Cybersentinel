import os
import time
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ThreatLookupAgent:
    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")

    def _retry_get(self, url, headers=None, params=None, retries=3, delay=2):
        """
        Retry GET request with exponential backoff and rate limit handling.
        """
        for i in range(retries):
            try:
                res = requests.get(url, headers=headers, params=params, timeout=10)
                if res.status_code == 200:
                    return res.json()
                elif res.status_code == 429:
                    print(f"[!] Rate limited. Retrying in {delay}s...")
                    time.sleep(delay * (i + 1))
                else:
                    print(f"[!] Unexpected status code {res.status_code} for {url}")
            except requests.RequestException as e:
                print(f"[!] Request failed: {e}")
                time.sleep(delay)
        return None

    def check_virustotal(self, indicator, itype):
        """
        Query VirusTotal for hash, IP, domain, or URL.
        """
        base_url = "https://www.virustotal.com/api/v3/" 

        try:
            if itype == "ip":
                return self._retry_get(f"{base_url}ip_addresses/{indicator}", headers={"x-apikey": self.vt_key})
            elif itype == "domain":
                return self._retry_get(f"{base_url}domains/{indicator}", headers={"x-apikey": self.vt_key})
            elif itype in ["MD5", "SHA1", "SHA256"]:
                return self._retry_get(f"{base_url}files/{indicator}", headers={"x-apikey": self.vt_key})
            elif itype == "url":
                # First submit the URL for analysis
                params = {"url": indicator}
                res = requests.post(f"{base_url}urls", headers={"x-apikey": self.vt_key}, data=params)
                if res.status_code == 200 or res.status_code == 201:
                    analysis_id = res.json().get('data', {}).get('id')
                    if analysis_id:
                        return self._retry_get(f"{base_url}analyses/{analysis_id}", headers={"x-apikey": self.vt_key})
                return None
        except Exception as e:
            print(f"[!] VT lookup error for {indicator}: {str(e)}")
        return None

    def check_abuseipdb(self, ip):
        """
        Check an IP against AbuseIPDB.
        """
        url = "https://api.abuseipdb.com/api/v2/check" 
        headers = {
            "Key": self.abuse_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "verbose": ""
        }
        return self._retry_get(url, headers=headers, params=params)

    def check_otx(self, indicator, itype):
        """
        Check an IOC using AlienVault OTX.
        """
        headers = {"X-OTX-API-KEY": self.otx_key}
        if itype in ["ip", "domain"]:
            return self._retry_get(f"https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general",  headers=headers)
        return None

    def lookup_ioc(self, ioc, ioc_type):
        """
        Perform all threat intelligence lookups on a single IOC.
        Returns a dictionary with results from VT, AbuseIPDB, and OTX.
        """
        vt_data = self.check_virustotal(ioc, ioc_type) if ioc_type in ["ip", "domain", "MD5", "SHA1", "SHA256", "url"] else None
        abuse_data = self.check_abuseipdb(ioc) if ioc_type == "ip" else None
        otx_data = self.check_otx(ioc, ioc_type) if ioc_type in ["ip", "domain"] else None

        return {
            "ioc": ioc,
            "type": ioc_type,
            "vt": vt_data,
            "abuseipdb": abuse_data,
            "otx": otx_data
        }