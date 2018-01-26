import re

from lib.modules.fingerprints import FingerprintPlugin


class Dotdefender(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'X-dotDefender-denied', item[0], re.I) is not None
            if _:
                return "dotDefender Web Application Firewall (Applicure Technologies)"
