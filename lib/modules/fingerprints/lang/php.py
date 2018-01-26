import re

from lib.modules.fingerprints import FingerprintPlugin


class Php(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'X-PHP-PID|PHP\S*|PHPSESSID', str(item)) is not None
        _ |= re.search(r'\.php$|\.phtml$', content) is not None
        if _:
            return "PHP"
