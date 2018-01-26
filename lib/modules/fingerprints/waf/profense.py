import re

from lib.modules.fingerprints import FingerprintPlugin


class Profense(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'PLBSID=', item[1], re.I) is not None
            _ = re.search(r'Profense', item[1], re.I) is not None
            if _:
                return "Profense Web Application Firewall (Armorlogic)"
