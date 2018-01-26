import re

from lib.modules.fingerprints import FingerprintPlugin


class Perl(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'\.pl$|\.cgi$', content) is not None
        if _:
            return "Perl"
