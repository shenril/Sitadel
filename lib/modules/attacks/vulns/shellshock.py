import re

from lib.utils.container import Services
from .. import AttackPlugin


class Shellshock(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        request = Services.get('request_factory')

        output.info('Scanning shellshock vuln..')
        try:
            resp = request.send(
                url=start_url,
                method="GET",
                payload=None,
                headers=None
            )
            if resp.status_code == 200:
                if re.search(r'*?/bin/bash', resp.content, re.I):
                    output.finding('That site is my be vulnerable to Shellshock.')
        except Exception as e:
            print(e)
