import re

from lib.modules.fingerprints import FingerprintPlugin


class Airlock(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'^AL[_-]SESS[_-]S=\S*', item[1], re.I) is not None
            _ |= re.search(r'X-Airlock-Test', item[0], re.I) is not None
            if _:
                return "InfoGuard Airlock (Phion/Ergon)"
