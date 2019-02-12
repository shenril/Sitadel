import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from lib.utils.container import Services
from .. import AttackPlugin


class LDAP(AttackPlugin):
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
            "IPWorksASP.LDAP"
        )
        for err in error:
            if re.search(err, data):
                return "LDAP Injection"

    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        datastore = Services.get('datastore')
        request = Services.get('request_factory')

        output.info('Checking ldap injection...')
        db = datastore.open('ldap.txt', 'r')
        dbfiles = [x.strip() for x in db]
        try:
            for payload in dbfiles:
                for url in crawled_urls:
                    # Current request parameters
                    params = dict(parse_qsl(urlsplit(url).query))
                    # Change the value of the parameters with the payload
                    tainted_params = {x: payload for x in params}

                    if len(tainted_params) > 0:
                        # Prepare the attack URL
                        attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                        resp = request.send(
                            url=attack_url,
                            method="GET",
                            payload=None,
                            headers=None
                        )
                        if self.errors(str(resp.content)):
                            output.finding('That site is may be vulnerable to LDAP Injection at %s' % url)

        except Exception as e:
            output.error("Error occured\nAborting this attack...\n")
            return
