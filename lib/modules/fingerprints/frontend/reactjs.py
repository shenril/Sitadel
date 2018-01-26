import re

from lib.modules.fingerprints import FingerprintPlugin


class Reactjs(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'react-[0-9\-\.]+.js', content, re.I) is not None
        _ = re.search(r'reactroot|reactid', content, re.I) is not None
        if _:
            return "ReactJS (Javascript)"
