import re

from lib.modules.fingerprints import FingerprintPlugin


class Aws(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'aws*', item[1], re.I) is not None
            _ |= re.search(r'x-amz-id-[0-2]', item[0], re.I) is not None
            _ |= re.search(r'x-amz-request-id', item[0], re.I) is not None
            if _:
                return 'Amazon Web Services Web Application Firewall (Amazon)'
