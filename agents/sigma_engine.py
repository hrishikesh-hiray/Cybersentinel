import os
import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

def scan_with_sigma(log_data):
    """
    Simulate Sigma rule matching against log data.
    Returns list of matched rule titles if any.
    """
    try:
        suspicious_patterns = {
            "Suspicious_CmdWhoami": ["cmd.exe /c whoami", "whoami"],
            "Suspicious_Download": ["certutil", "bitsadmin", "download"],
            "Suspicious_Registry": ["reg add", "reg delete", "reg query"]
        }

        matched_rules = []
        for rule_name, keywords in suspicious_patterns.items():
            if any(kw.lower() in log_data.lower() for kw in keywords):
                matched_rules.append(rule_name)

        return matched_rules

    except Exception as e:
        print(f"[!] Sigma Error: {e}")
        return []
