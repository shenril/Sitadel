import re
from sitadel.utils.container import Services
from .. import AttackPlugin


class Xss(AttackPlugin):
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        # Match the payload literally: it is HTML, not a regex.
        if resp.status_code == 200 and re.search(re.escape(payload), resp.text, re.I):
            return "Cross Site Scripting (XSS)"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking cross site scripting...")
        with self.datastore.open("xss.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db]
        self.run_injection(payloads, crawled_urls, self.detect)
