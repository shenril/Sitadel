import re

from lib.modules.fingerprints import FingerprintPlugin


class Server(FingerprintPlugin):
    def process(self, headers, content):
        server = None
        try:
            for item in headers.items():
                if re.search(r'server', item[0], re.I):
                    server = item[1]
            # FIXME Fix the access to request URL
            # if server is None:
            #     resp = Request().send(Request().url, headers={'Expect': 'Linguini'})
            #     for item in resp.headers.items():
            #         if re.search(r'server', item[0], re.I): server = item[1]
            return server
        except Exception as e:
            print(e)
