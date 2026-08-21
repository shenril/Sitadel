from urllib.parse import urlparse

from dns.resolver import NXDOMAIN, NoAnswer, Resolver, Timeout

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.modules.fingerprints import FingerprintPlugin
from sitadel.utils.container import Services


class Akamai(FingerprintPlugin):
    level = Risk.NO_DANGER

    def process(self, headers, content):
        request = Services.get("request_factory")
        hostname = urlparse(request.url).hostname
        try:
            resolver = Resolver(configure=False)
            resolver.nameservers = [settings.dns_resolver]
            resolver.timeout = 2
            resolver.lifetime = 2

            dns_query = resolver.query(hostname + ".edgekey.net", "A")

            if len(dns_query) > 0:
                return "Akamai CDN"

        except NXDOMAIN:
            pass
        except NoAnswer:
            pass
        except Timeout:
            pass
