import re
from urllib.parse import parse_qsl, urlencode, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.utils.container import Services
from lib.config.settings import Risk
from .. import AttackPlugin


class LDAP(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    datastore = Services.get("datastore")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def errors(self, data):
        error = (
            "supplied argument is not a valid ldap",
            "javax.naming.NameNotFoundException",
            "javax.naming.directory.InvalidSearchFilterException",
            "Invalid DN syntax",
            "LDAPException|com.sun.jndi.ldap",
            "Search: Bad search filter",
            "Protocol error occurred",
            "Size limit has exceeded",
            "The alias is invalid",
            "Module Products.LDAPMultiPlugins",
            "Object does not exist",
            "The syntax is invalid",
            "A constraint violation occurred",
            "An inappropriate matching occurred",
            "Unknown error occurred",
            "The search filter is incorrect",
            "Local error occurred",
            "The search filter is invalid",
            "The search filter cannot be recognized",
            "IPWorksASP.LDAP",
        )
        for err in error:
            if re.search(err, data):
                return "LDAP Injection"

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
                if self.errors(resp.text):
                    self.output.finding(
                        "That site is may be vulnerable to LDAP Injection at %s\nInjection: %s"
                        % (url, payload)
                    )
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking ldap injection...")
        db = self.datastore.open("ldap.txt", "r")
        dbfiles = [x.strip() for x in db]

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

