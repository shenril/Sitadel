import re

from lib.modules.fingerprints import FingerprintPlugin


class Cloudflare(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'cloudflare[-nginx]', item[1], re.I) is not None
            _ |= re.search(r'__cfduid=', item[1], re.I) is not None
            _ |= re.search(r'cf-ray', item[0], re.I) is not None
            if _:
                return "CloudFlare Web Application Firewall (CloudFlare)"
