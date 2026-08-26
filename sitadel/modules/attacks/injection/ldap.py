import re
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
from .. import AttackPlugin

# LDAP-error signatures, combined into one compiled alternation and matched
# once per response (was 20 separate searches on the per-payload hot path).
_LDAP_ERRORS = re.compile("|".join((
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
)))


class LDAP(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    datastore = Services.get("datastore")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def errors(self, data):
        return "LDAP Injection" if _LDAP_ERRORS.search(data) else None

    def detect(self, resp, payload):
        return self.errors(resp.text)

    def process(self, start_url, crawled_urls):
        self.output.info("Checking ldap injection...")
        with self.datastore.open("ldap.txt", "r") as db:
            payloads = [x.strip() for x in db]
        self.run_injection(payloads, crawled_urls, self.detect)
