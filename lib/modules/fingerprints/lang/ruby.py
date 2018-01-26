import re

from lib.modules.fingerprints import FingerprintPlugin


class Ruby(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r"mod_rack|phusion|passenger", item[1], re.I) is not None
        _ |= re.search(r'\.rb$|\.rhtml$', content) is not None
        if _:
            return "Ruby"
