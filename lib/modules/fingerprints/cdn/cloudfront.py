import re
from urllib.parse import urlparse

from dns.resolver import NXDOMAIN, NoAnswer, Resolver, Timeout

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services


class CloudFront(FingerprintPlugin):
    level = Risk.NO_DANGER

    def process(self, headers, content):
        request = Services.get("request_factory")
        hostname = urlparse(request.url).hostname
        _ = False
        try:
            resolver = Resolver(configure=False)
            resolver.nameservers = [settings.dns_resolver]
            resolver.timeout = 2
            resolver.lifetime = 2

            dns_query = resolver.query(hostname, "CNAME")

            if len(dns_query) > 0:
                for answer in dns_query:
                    _ |= re.search(r"cloudfront\.net", str(answer), re.I) is not None
            if _:
                return "CloudFront CDN (Amazon)"
        except NoAnswer:
            pass
        except NXDOMAIN:
            pass
        except Timeout:
            pass
