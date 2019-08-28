import re

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services

class Joomla(FingerprintPlugin):
    logger = Services.get("logger")
    def process(self, headers, content):
        _ = False
        try:
            _ = re.search(
                r'/index.php?option=(\S*)|<meta name="generator" content="Joomla*|Powered by <a href="http://www.joomla.org">Joomla!</a>*',
                content) is not None
            if _:
                if re.search('/templates/*', content, re.I):
                    return "Joomla"
        except Exception as e:
            self.logger.error(e)
