import re

from lib.modules.fingerprints import FingerprintPlugin


class Wordpress(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        try:
            for x in ('/wp-admin/', '/wp-content/', '/wp-includes/', '<meta name="generator" content="WordPress'):
                _ = re.search(x, content) is not None
            if _:
                return "Wordpress"
        except Exception as e:
            print(e)
