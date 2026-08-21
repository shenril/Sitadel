import re

from sitadel.modules.fingerprints import FingerprintPlugin
from sitadel.utils.container import Services

class Server(FingerprintPlugin):
    logger = Services.get("logger")
    def process(self, headers, content):
        server = None
        try:
            for item in headers.items():
                if re.search(r'server', item[0], re.I):
                    server = item[1]
            return server
        except Exception as e:
            self.logger.error(e)
