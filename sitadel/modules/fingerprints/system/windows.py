import re

from sitadel.modules.fingerprints import FingerprintPlugin


class Windows(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'windows|win32', str(item), re.I) is not None
            if _:
                return "Windows"
