import re

from lib.modules.fingerprints import FingerprintPlugin


class Netcontinuum(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'NCI__SessionId=', item[1], re.I) is not None
            if _:
                return "NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)"
