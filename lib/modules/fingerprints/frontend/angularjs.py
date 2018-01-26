import re

from lib.modules.fingerprints import FingerprintPlugin


class Angularjs(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'ng-app', content, re.I) is not None
        _ |= re.search(r'ng-version', content, re.I) is not None
        _ |= re.search(r'app-root', content, re.I) is not None
        if _:
            return "AngularJS (Google)"
