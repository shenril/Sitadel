import re

from lib.utils.container import Services
from .. import AttackPlugin


class HtmlObject(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking html object..")
        try:
            resp = request.send(url=start_url, method="GET", payload=None, headers=None)
            if re.search(r"<object.*?>.*?<\/object>", resp.text, re.I):
                output.finding(
                    "Found HTML Object, logs the existence of HTML object tags at:"
                    % request.url
                )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
