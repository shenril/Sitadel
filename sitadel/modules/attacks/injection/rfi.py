import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
from .. import AttackPlugin


class Rfi(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def attack(self, payload, url):
        flag = r"root:/root:/bin/bash|default=multi([0])disk([0])rdisk([0])partition([1])\\WINDOWS"
        try:
            # Rebuild the URL with the payload injected in every parameter
            attack_url = self.taint_url(url, payload)
            if attack_url is not None:
                self.output.debug("Testing: %s" % attack_url)
                resp = self.request.send(
                    url=attack_url, method="GET", payload=None, headers=None
                )
                if re.search(flag, resp.text):
                    self.output.finding(
                        "That site is may be vulnerable to Remote File Inclusion (RFI) at %s\nInjection: %s"
                        % (url, payload)
                    )
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking remote file inclusion...")
        with self.datastore.open("rfi.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db]
        # Submit the whole payload x url matrix to a single bounded pool so
        # every task is awaited and interrupts are handled once.
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(self.attack, payload, url)
                for payload in payloads
                for url in crawled_urls
            ]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
