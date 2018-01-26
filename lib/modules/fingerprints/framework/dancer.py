import re

from lib.modules.fingerprints import FingerprintPlugin


class Dancer(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ |= re.search(r'Dancer|dancer\.session=.*', item[1], re.I) is not None
        if _:
            return "Dancer (Perl)"
