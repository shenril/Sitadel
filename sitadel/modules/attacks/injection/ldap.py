import re
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
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
        return None

    def detect(self, resp, payload):
        return self.errors(resp.text)

    def process(self, start_url, crawled_urls):
        self.output.info("Checking ldap injection...")
        with self.datastore.open("ldap.txt", "r") as db:
            payloads = [x.strip() for x in db]
        self.run_injection(payloads, crawled_urls, self.detect)
