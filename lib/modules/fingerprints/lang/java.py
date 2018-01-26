import re

from lib.modules.fingerprints import FingerprintPlugin


class Java(FingerprintPlugin):
    def process(self, headers, content):
        _ = False
        for item in headers.items():
            _ = re.search(r'Java|Servlet|JSP|JBoss|Glassfish|Oracle|JRE|JDK|JSESSIONID', str(item)) is not None
            if not _:
                _ |= re.search(r'\.jsp$|\.jspx$|.do$|\.wss$|\.action$', content) is not None
            if _:
                return "Java"
