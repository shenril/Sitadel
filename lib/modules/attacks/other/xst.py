import re

from lib.utils.container import Services
from .. import AttackPlugin


class XST(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")

        output.info("Checking cross site tracing..")
        try:
            resp = request.send(
                url=start_url,
                method="TRACE",
                payload=None,
                headers={"Sitadel": "PastaXST"},
            )
            if re.search("Sitadel: *?PastaXST", resp.text, re.I):
                output.finding(
                    "That site is may be vulnerable to Cross Site Tracing (XST) vulnerability."
                )
        except Exception as e:
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
