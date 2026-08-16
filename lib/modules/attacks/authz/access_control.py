from lib.config.settings import Risk
from lib.request.request import SingleRequest
from lib.utils.container import Services
from .. import AttackPlugin
from .idutils import object_refs, similar


class AccessControl(AttackPlugin):
    """Broken Access Control: object endpoints reachable without a session.

    For each crawled URL that references an object id, compare the response
    seen by the authenticated session against an anonymous request. If the
    anonymous request gets an equivalent 200 response, the object is served
    without authentication (OWASP A01 / CWE-284).
    """

    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        auth = getattr(request, "authenticator", None)
        if not (auth is not None and auth.has_login):
            output.info(
                "Skipping access-control checks (need an authenticated session "
                "to compare against)"
            )
            return

        output.info("Checking broken access control...")
        anonymous = SingleRequest(timeout=request.timeout, verify=request.verify)
        seen = set()
        for url in crawled_urls or []:
            if url in seen or not object_refs(url):
                continue
            seen.add(url)
            try:
                authed = request.send(url=url, method="GET")
                anon = anonymous.send(url=url, method="GET")
            except Exception as err:
                logger.error(err)
                continue
            if authed is None or anon is None:
                continue
            if (
                authed.status_code == 200
                and anon.status_code == 200
                and similar(authed.text, anon.text)
            ):
                output.finding(
                    "Possible Broken Access Control: %s is served without "
                    "authentication (OWASP A01)" % url
                )
