def score_risk(threat_data):
    score = 0.0
    reasons = []

    # VirusTotal detections
    if threat_data.get("vt"):
        try:
            stats = threat_data["vt"]["data"]["attributes"].get("last_analysis_stats", {})
            vt_score = stats.get("malicious", 0) * 1.5
            score += vt_score
            if stats.get("malicious", 0) > 0:
                reasons.append(f"VT detection ({stats['malicious']} engines)")
        except Exception as e:
            print("[!] VT score error:", str(e))

    # AbuseIPDB reports
    if threat_data.get("abuseipdb"):
        try:
            reports = threat_data["abuseipdb"]["data"].get("totalReportCount", 0)
            abuse_score = min(reports / 4, 4)
            score += abuse_score
            if reports > 0:
                reasons.append(f"AbuseIPDB reports ({reports})")
        except Exception as e:
            print("[!] AbuseIPDB score error:", str(e))

    # OTX pulses
    if threat_data.get("otx"):
        try:
            pulses = threat_data["otx"].get("pulse_info", {}).get("count", 0)
            otx_score = min(pulses * 2, 5)
            score += otx_score
            if pulses > 0:
                reasons.append(f"OTX pulses ({pulses})")
        except Exception as e:
            print("[!] OTX score error:", str(e))

    # Sigma rule match
    if threat_data.get("sigma") and len(threat_data["sigma"]) > 0:
        sigma_score = 2.0
        score += sigma_score
        reasons.append(f"Sigma rule match ({', '.join(threat_data['sigma'])})")

    # Final cap and rounding
    score = round(min(score, 10), 1)
    level = "Safe" if score <= 3 else "Suspicious" if score <= 6 else "Malicious"

    return {"score": score, "level": level, "reasons": reasons}