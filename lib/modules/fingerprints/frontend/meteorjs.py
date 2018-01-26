import re

from lib.modules.fingerprints import FingerprintPlugin


class Meteorjs(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'__meteor_runtime_config__', content, re.I) is not None
        if _:
            return "MeteorJS (Javascript)"
