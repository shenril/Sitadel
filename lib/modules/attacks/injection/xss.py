import re
from urllib.parse import parse_qsl, urlencode, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.utils.container import Services
from .. import AttackPlugin


class Xss(AttackPlugin):
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def attack(self, payload, url):
        try:
            # Current request parameters
            params = dict(parse_qsl(urlsplit(url).query))
            # Change the value of the parameters with the payload
            tainted_params = {x: payload for x in params}

            if len(tainted_params) > 0:
                # Prepare the attack URL
                attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                self.output.debug("Testing: %s" % attack_url)
                resp = self.request.send(
                    url=attack_url, method="GET", payload=None, headers=None
                )
                if resp.status_code == 200:
                    if re.search(payload[0], resp.text, re.I):
                        self.output.finding(
                            "That site may be vulnerable to Cross Site Scripting (XSS) at %s \nInjection: %s"
                            % (url, payload[0])
                        )
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        db = self.datastore.open("xss.txt", "r")
        dbfiles = [x.split("\n") for x in db]
        self.output.info("Checking cross site scripting...")
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

