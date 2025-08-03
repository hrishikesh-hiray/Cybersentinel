import requests

def get_geo_info(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json") 
    if response.status_code == 200:
        data = response.json()
        return {
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "location": data.get("loc")
        }
    return {}