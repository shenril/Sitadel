import re

from lib.modules.fingerprints import FingerprintPlugin


class Prototype(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'prototype.js', content, re.I) is not None
        _ |= re.search(r'prototype-[0-9\-\.]+.js', content, re.I) is not None
        if _:
            return "Prototype (Javascript)"
