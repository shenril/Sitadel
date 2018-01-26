import re

from lib.modules.fingerprints import FingerprintPlugin


class Sucuri(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'Sucuri|Cloudproxy', item[1], re.I) is not None
            _ |= re.search(r'X-Sucuri-ID', item[0], re.I) is not None
            if _:
                return "CloudProxy WebSite Firewall (Sucuri)"
