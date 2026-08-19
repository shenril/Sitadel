import re
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
from .. import AttackPlugin


class Rfi(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    _FLAG = r"root:/root:/bin/bash|default=multi([0])disk([0])rdisk([0])partition([1])\\WINDOWS"

    def detect(self, resp, payload):
        if re.search(self._FLAG, resp.text):
            return "Remote File Inclusion (RFI)"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking remote file inclusion...")
        with self.datastore.open("rfi.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db]
        self.run_injection(payloads, crawled_urls, self.detect)
