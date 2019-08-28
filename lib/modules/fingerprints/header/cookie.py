import re

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services


class Cookie(FingerprintPlugin):
    output = Services.get("output")
    def process(self, headers, content):
        if 'set-cookie' in headers:
            cookie = headers['set-cookie']
        else:
            cookie = None
        if cookie is not None:
            if re.search(r'domain=\S*', cookie, re.I):
                self.output.finding(
                    'Cookies are only accessible to this domain: %s' % re.findall(r'domain=(.+?)[\;]', cookie, re.I)[0])
            if not re.search('httponly', cookie, re.I):
                self.output.finding('Cookies created without HTTPOnly Flag.')
            if not re.search('secure', cookie, re.I):
                self.output.finding('Cookies created without Secure Flag.')
