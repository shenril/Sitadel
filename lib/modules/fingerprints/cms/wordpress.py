import re

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services

class Wordpress(FingerprintPlugin):
    logger = Services.get("logger")
    def process(self, headers, content):
        _ = False
        try:
            for x in ('/wp-admin/', '/wp-content/', '/wp-includes/', '<meta name="generator" content="WordPress'):
                _ = re.search(x, content) is not None
            if _:
                return "Wordpress"
        except Exception as e:
            self.logger.error(e)
