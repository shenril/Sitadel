import re

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services


class Headers(FingerprintPlugin):
    output = Services.get("output")
    logger = Services.get("logger")
    def process(self, headers, content):
        fields = ('Accept',
                  'Accept-Charset',
                  'Accept-Encoding',
                  'Accept-Language',
                  'Accept-Datetime',
                  'Authorization',
                  'Connection',
                  'Cookie',
                  'Content-Length',
                  'Content-MD5',
                  'Content-Type',
                  'Expect',
                  'From',
                  'Host',
                  'If-Match',
                  'If-Modified-Since',
                  'If-None-Match',
                  'If-Range',
                  'If-Unmodified-Since',
                  'Max-Forwards',
                  'Origin',
                  'Pragma',
                  'Proxy-Authorization',
                  'Range',
                  'Referer',
                  'User-Agent',
                  'Upgrade',
                  'Via',
                  'Warning',
                  'X-Requested-With',
                  'X-Forwarded-For',
                  'X-Forwarded-Host',
                  'X-Forwarded-Proto',
                  'Front-End-Https',
                  'X-Http-Method-Override',
                  'X-ATT-DeviceId',
                  'X-Wap-Profile',
                  'Proxy-Connection',
                  'Accept-Ranges',
                  'Age',
                  'Allow',
                  'Cache-Control',
                  'Content-Encoding',
                  'Content-Language',
                  'Content-Length',
                  'Content-Location',
                  'Content-MD5',
                  'Content-Disposition',
                  'Content-Range',
                  'Content-Type',
                  'Date',
                  'ETag',
                  'Expires',
                  'Last-Modified',
                  'Link',
                  'Location',
                  'Proxy-Authenticate',
                  'Refresh',
                  'Retry-After',
                  'Server',
                  'Set-Cookie',
                  'Status',
                  'Strict-Transport-Security',
                  'Trailer',
                  'Transfer-Encoding',
                  'Vary',
                  'WWW-Authenticate',
                  'X-Frame-Options',
                  'Public-Key-Pins',
                  'X-XSS-Protection',
                  'Content-Security-Policy',
                  'X-Content-Security-Policy',
                  'X-WebKit-CSP',
                  'X-Content-Type-Options',
                  'X-Powered-By',
                  'Keep-Alive',
                  'Content-language',
                  'X-UA-Compatible'
                  )

        if not re.search(r'X-Frame-Options', str(headers.keys()), re.I):
            self.output.finding('X-Frame-Options header is not present.')

        if not re.search(r'Strict-Transport-Security', str(headers.keys()), re.I):
            self.output.finding('Strict-Transport-Security header is not present.')

        if not re.search(r'x-xss-protection', str(headers.keys()), re.I):
            self.output.finding('X-XSS-Protection header is not present.')
        try:
            for key in headers.keys():
                if key not in fields:
                    self.output.finding('Uncommon header "%s" found, with contents: %s' % (key, headers[key]))
        except Exception as e:
            self.logger.error(e)
