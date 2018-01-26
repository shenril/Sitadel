import re

from lib.modules.fingerprints import FingerprintPlugin


class Laravel(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'laravel_session=', item[1], re.I) is not None
            if _:
                return "Laravel (PHP)"
