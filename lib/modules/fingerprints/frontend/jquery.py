import re

from lib.modules.fingerprints import FingerprintPlugin


class Jquery(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'jquery-[0-9\-\.]+.js|jquery', content, re.I) is not None
        if _:
            return "JQuery (Javascript)"
