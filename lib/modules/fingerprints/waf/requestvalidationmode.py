import re

from lib.modules.fingerprints import FingerprintPlugin


class Requestvalidationmode(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        _ = re.search(r'ASP.NET has detected data in the request that is potentially dangerous', content,
                      re.I) is not None
        _ |= re.search(r'Request Validation has detected a potentially dangerous client input value', content,
                       re.I) is not None
        if _:
            return "ASP.NET RequestValidationMode (Microsoft)"
