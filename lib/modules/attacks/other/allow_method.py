import re

from lib.utils.container import Services
from .. import AttackPlugin


class AllowMethod(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        datastore = Services.get("datastore")
        logger = Services.get("logger")

        output.info("Checking http allow methods..")
        db = datastore.open("allowmethod.txt", "r")
        dbfiles = [x.strip() for x in db.readlines()]
        try:
            for method in dbfiles:
                resp = request.send(
                    url=start_url, method=str(method), payload=None, headers=None
                )
                if re.search(r"allow|public", str(resp.headers.keys()), re.I):
                    allow = resp.headers["allow"]
                    if allow is None:
                        allow = resp.headers["public"]
                    if allow is not None and allow != "":
                        output.finding("HTTP Allow Method: %s" % allow)
                        break
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
