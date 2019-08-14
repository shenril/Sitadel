import re

from lib.utils.container import Services
from lib.config.settings import Risk
from .. import AttackPlugin


class Shellshock(AttackPlugin):
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Scanning shellshock vuln..")
        try:
            resp = request.send(url=start_url, method="GET", payload=None, headers=None)
            if resp.status_code == 200:
                if re.search(r".*/bin/bash", resp.text, re.I):
                    output.finding("That site is my be vulnerable to Shellshock.")
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
