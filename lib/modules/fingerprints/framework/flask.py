import re

from lib.modules.fingerprints import FingerprintPlugin


class Flask(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'flask', item[1], re.I) is not None
            if _:
                return "Flask (Python)"
