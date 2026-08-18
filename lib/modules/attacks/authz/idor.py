from lib.config.settings import Risk
from lib.utils.container import Services
from .. import AttackPlugin
from .idutils import different, object_refs, replace_id


class Idor(AttackPlugin):
    """Insecure Direct Object Reference: neighbouring ids return other objects.

    For each crawled URL with a numeric object id, request the neighbouring id
    (value + 1). If it returns a distinct, valid 200 object, the endpoint likely
    exposes other users' objects by id manipulation (OWASP A01 / CWE-639).
    """

    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking insecure direct object references (IDOR)...")
        seen = set()
        for url in crawled_urls or []:
            if url in seen:
                continue
            seen.add(url)
            for location, key, value in object_refs(url):
                if not value.isdigit():
                    continue
                neighbour = replace_id(url, location, key, int(value) + 1)
                try:
                    base = request.send(url=url, method="GET")
                    other = request.send(url=neighbour, method="GET")
                except Exception as err:
                    logger.error(err)
                    continue
                if base is None or other is None:
                    continue
                if other.status_code == 200 and different(base.text, other.text):
                    output.finding(
                        "Possible IDOR at %s: changing %s from %s to %s returns "
                        "a different valid object (OWASP A01)"
                        % (url, key, value, int(value) + 1)
                    )
                    break  # one signal per URL is enough
