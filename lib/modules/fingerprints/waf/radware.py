import re

from lib.modules.fingerprints import FingerprintPlugin


class Radware(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'X-SL-CompState', item[0], re.I) is not None
            if _:
                return "AppWall Web Application Firewall (Radware)"
