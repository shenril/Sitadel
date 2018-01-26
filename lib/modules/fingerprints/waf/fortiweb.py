import re

from lib.modules.fingerprints import FingerprintPlugin


class Fortiweb(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'FORTIWAFSID=', item[1], re.I) is not None
            if _:
                return "FortiWeb Web Application Firewall (Fortinet)"
