import re
from sitadel.utils.container import Services
from .. import AttackPlugin

_XPATH_ERRORS = re.compile(r"XPATH syntax error:|XPathException", re.I)


class Xpath(AttackPlugin):
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        if _XPATH_ERRORS.search(resp.text):
            return "XPath Injection"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking xpath injection...")
        with self.datastore.open("xpath.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db]
        self.run_injection(payloads, crawled_urls, self.detect)
