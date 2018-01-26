import re

from lib.modules.fingerprints import FingerprintPlugin


class Bsd(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'\S*BSD', str(item), re.I) is not None
            if _:
                return "BSD"
