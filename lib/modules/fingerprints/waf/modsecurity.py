import re

from lib.modules.fingerprints import FingerprintPlugin


class Modsecurity(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'Mod_Security|NOYB', item[1], re.I) is not None
            if _:
                return "ModSecurity Web Application Firewall (Trustwave)"
