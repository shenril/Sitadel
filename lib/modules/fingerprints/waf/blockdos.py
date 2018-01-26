import re

from lib.modules.fingerprints import FingerprintPlugin


class Blockdos(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'BlockDos[\.net]*', item[1], re.I) is not None
            if _:
                return "BlockDoS"
