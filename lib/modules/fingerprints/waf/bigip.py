import re

from lib.modules.fingerprints import FingerprintPlugin


class Bigip(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'BigIP|BIGipServer', item[1], re.I) is not None
            _ |= re.search(r'TS\w{4,}=', item[1], re.I) is not None
            _ |= re.search(r'F5', item[1], re.I) is not None
            if _:
                return "BIG-IP Application Security Manager (F5 Networks)"
