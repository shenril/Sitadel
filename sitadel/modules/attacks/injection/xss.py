import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from sitadel.utils.container import Services
from .. import AttackPlugin


class Xss(AttackPlugin):
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def attack(self, payload, url):
        try:
            # Rebuild the URL with the payload injected in every parameter
            attack_url = self.taint_url(url, payload)
            if attack_url is not None:
                self.output.debug("Testing: %s" % attack_url)
                resp = self.request.send(
                    url=attack_url, method="GET", payload=None, headers=None
                )
                if resp.status_code == 200:
                    # Match the payload literally: it is HTML, not a regex
                    if re.search(re.escape(payload), resp.text, re.I):
                        self.output.finding(
                            "That site may be vulnerable to Cross Site Scripting (XSS) at %s \nInjection: %s"
                            % (url, payload)
                        )
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking cross site scripting...")
        with self.datastore.open("xss.txt", "r") as db:
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

