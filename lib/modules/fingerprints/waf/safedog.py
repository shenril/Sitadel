import re

from lib.modules.fingerprints import FingerprintPlugin


class Safedog(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'WAF/2\.0', item[1], re.I) is not None
            _ |= re.search(r'Safedog', item[1], re.I) is not None
            if _:
                return "Safedog Web Application Firewall (Safedog)"
