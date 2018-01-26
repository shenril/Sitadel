import re

from lib.modules.fingerprints import FingerprintPlugin


class Incapsula(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'incap_ses|visid_incap|Incapsula', item[1], re.I) is not None
            if _:
                return "Incapsula Web Application Firewall (Incapsula/Imperva)"
