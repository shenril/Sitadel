import re

from lib.utils.container import Services
from .. import AttackPlugin


class Dav(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        request = Services.get('request_factory')

        output.info('Checking webdav..')
        try:
            resp = request.send(
                url=start_url,
                method="PROPFIND",
                payload=None,
                headers={
                    'Host': 'localhost',
                    'Content-Length': '0'
                }
            )
            if re.search('<a:href>http://localhost/</a:href>', resp.content, re.I):
                output.finding(
                    'That site is may be vulnerable to WebDAV authentication bypass vulnerability, (CVE-2009-1535).')
        except Exception as e:
            print(e)
