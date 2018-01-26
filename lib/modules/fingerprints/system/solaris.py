import re

from lib.modules.fingerprints import FingerprintPlugin


class Solaris(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'solaris|sunos|opensolaris|sparc64|sparc', str(item), re.I) is not None
            if _:
                return "Solaris"
