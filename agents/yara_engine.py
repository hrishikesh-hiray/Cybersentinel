import yara

def scan_with_yara(data):
    rules = """
rule ExampleRule {
    strings:
        $a = "malware" nocase
    condition:
        $a
}
"""
    compiled_rules = yara.compile(source=rules)
    matches = compiled_rules.match(data=data)
    return [match.rule for match in matches]