import re

from lib.modules.fingerprints import FingerprintPlugin


class Webknight(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'Webknight', item[1], re.I) is not None
            if _:
                return "WebKnight Application Firewall (AQTRONIX)"
