import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.utils.container import Services
from .. import AttackPlugin


class Xpath(AttackPlugin):
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
                if re.search(r"XPATH syntax error:|XPathException", resp.text, re.I):
                    self.output.finding(
                        "That site may be vulnerable to XPath Injection at %s\nInjection: %s"
                        % (url, payload)
                    )
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking xpath injection...")
        db = self.datastore.open("xpath.txt", "r")
        dbfiles = [x.rstrip("\n") for x in db]
        for payload in dbfiles:
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.attack, payload, url) for url in crawled_urls
                ]
        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            executor.shutdown(False)
            raise

