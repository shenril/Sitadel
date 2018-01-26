import re

from lib.modules.fingerprints import FingerprintPlugin


class Python(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'python|zope|zserver|wsgi|plone|_ZopeId', item[1], re.I) is not None
        _ |= re.search(r'\.py$', content) is not None
        if _:
            return "Python"
