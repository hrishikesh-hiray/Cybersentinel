import re

def extract_iocs(text):
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': [],
        'emails': []
    }

    # IPs
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, text)))

    # Domains (Improved pattern)
    domain_pattern = r'((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
    iocs['domains'] = [d.strip() for d in re.findall(domain_pattern, text)]

    # URLs (fix obfuscations)
    url_pattern = r'(?:hxxps?|http[s]?)://[^\s"\'>]+'
    urls = re.findall(url_pattern, text)
    iocs['urls'] = [
        url.replace('hxxp', 'http').replace('[.]', '.')
        for url in urls
    ]

    # Hashes
    hash_patterns = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }
    for htype, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        iocs['hashes'].extend([(match, htype.upper()) for match in matches])

    # Emails
    email_pattern = r'\b[\w.-]+@[\w.-]+\.\w+\b'
    iocs['emails'] = list(set(re.findall(email_pattern, text)))

    return iocs