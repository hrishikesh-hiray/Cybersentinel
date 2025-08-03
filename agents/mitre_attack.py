from mitreattack.stix20 import MitreAttackData
import os

def map_to_mitre(ioc_type):
    stix_file = os.path.join(os.getcwd(), "enterprise-attack.json")

    if not os.path.exists(stix_file):
        return "MITRE ATT&CK dataset not found"

    try:
        attack_data = MitreAttackData(stix_file)
        tactics = attack_data.get_tactics()

        if ioc_type == "ip":
            return "Command and Control"
        elif ioc_type == "hash":
            return "Malware"
        elif ioc_type == "url":
            return "Initial Access"
        else:
            return "Unknown"
    except Exception as e:
        return f"Error: {str(e)}"