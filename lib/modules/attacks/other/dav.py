import re

from lib.utils.container import Services
from lib.config.settings import Risk
from .. import AttackPlugin


class Dav(AttackPlugin):
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking webdav..")
        try:
            resp = request.send(
                url=start_url,
                method="PROPFIND",
                payload=None,
                headers={"Host": "localhost", "Content-Length": "0"},
            )
            if re.search("<a:href>http://localhost/</a:href>", resp.text, re.I):
                output.finding(
                    "That site is may be vulnerable to WebDAV authentication bypass vulnerability, (CVE-2009-1535)."
                )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
