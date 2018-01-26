import re

from lib.modules.fingerprints import FingerprintPlugin


class Knockout(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'knockout-[0-9\-\.]+.js', content, re.I) is not None
        if _:
            return "Knockout (Javascript)"
