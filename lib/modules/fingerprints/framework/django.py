import re

from lib.modules.fingerprints import FingerprintPlugin


class Django(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'csrftoken=', item[1], re.I) is not None
            if _:
                return "Django (Python)"
