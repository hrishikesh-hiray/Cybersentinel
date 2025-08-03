import csv
import json
from stix2 import Indicator, Bundle

def export_csv(results, filename="report.csv"):
    fieldnames = ["IOC", "Type", "Risk Level", "Score", "Action", "Reason", "Geo", "MITRE"]

    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "IOC": r.get("ioc", ""),
                "Type": r.get("type", ""),
                "Risk Level": r.get("risk", {}).get("level", ""),
                "Score": r.get("risk", {}).get("score", ""),
                "Action": r.get("action", {}).get("action", ""),
                "Reason": ", ".join(r.get("risk", {}).get("reasons", [])),
                "Geo": r.get("geo", {}).get("country_name", "N/A"),
                "MITRE": ", ".join(r.get("mitre", [])) if isinstance(r.get("mitre"), list) else r.get("mitre", "N/A")
            })

def export_stix(results, filename="report.stix"):
    indicators = []

    for r in results:
        pattern = ""
        if r["type"] == "ip":
            pattern = f"[ipv4-addr:value = '{r['ioc']}']"
        elif r["type"] == "domain":
            pattern = f"[domain-name:value = '{r['ioc']}']"
        elif r["type"] in ["md5", "sha1", "sha256"]:
            pattern = f"[file:hashes.'{r['type']}' = '{r['ioc']}']"
        elif r["type"] == "url":
            pattern = f"[url:value = '{r['ioc']}']"

        if pattern:
            indicators.append(Indicator(pattern=pattern, pattern_type="stix"))

    bundle = Bundle(objects=indicators)
    with open(filename, "w") as f:
        f.write(str(bundle))
