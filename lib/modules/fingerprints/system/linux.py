import re

from lib.modules.fingerprints import FingerprintPlugin


class Linux(FingerprintPlugin):
    def process(self, headers, content):
        for item in headers.items():
            _ = re.findall(
                r'linux|ubuntu|gentoo|debian|dotdeb|centos|redhat|sarge|etch|lenny|squeeze|wheezy|jessie|red hat|scientific linux',
                str(item), re.I)
            if _:
                if len(_) == 2:
                    return _[0]
                else:
                    return _[0]
