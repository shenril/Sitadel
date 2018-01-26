import re

from lib.modules.fingerprints import FingerprintPlugin


class Fuelphp(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'fuelcid=', item[1], re.I) is not None
            _ |= re.search(r'Powered by <a href="http://fuelphp.com">FuelPHP</a>', content) is not None
            if _:
                return "FuelPHP (PHP)"
