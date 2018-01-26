import re

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.output import Output


class Cookie(FingerprintPlugin):
    def process(self, headers, content):
        if 'set-cookie' in headers:
            cookie = headers['set-cookie']
        else:
            cookie = None
        if cookie is not None:
            if re.search(r'domain=\S*', cookie, re.I):
                Output().finding(
                    'Cookies are only accessible to this domain: %s' % re.findall(r'domain=(.+?)[\;]', cookie, re.I)[0])
            if not re.search('httponly', cookie, re.I):
                Output().finding('Cookies created without HTTPOnly Flag.')
            if not re.search('secure', cookie, re.I):
                Output().finding('Cookies created without Secure Flag.')
