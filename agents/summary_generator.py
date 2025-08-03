def generate_summary(results):
    table = "| IOC | Type | Risk Level | Score | Action | Reason |\n"
    table += "|-----|------|------------|-------|--------|--------|\n"
    for result in results:
        ioc = result["ioc"]
        itype = result["type"]
        score = result["risk"]["score"]
        level = result["risk"]["level"]
        action = result["action"]["action"]
        reason = ", ".join(result["risk"]["reasons"])
        table += f"| {ioc} | {itype} | {level} | {score} | {action} | {reason or 'No match'} |\n"
    return table