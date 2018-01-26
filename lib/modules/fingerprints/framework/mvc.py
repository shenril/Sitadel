import re

from lib.modules.fingerprints import FingerprintPlugin


class Mvc(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'x-aspnetmvc-version|__requestverificationtoken', str(item), re.I) is not None
            if _:
                return "ASP.NET MVC"
