"""CORS misconfiguration check — issue #72.

Sends a request carrying a foreign ``Origin`` and inspects the CORS response
headers. Reflecting an attacker-controlled origin — or ``*`` — together with
``Access-Control-Allow-Credentials: true`` lets a malicious site read
authenticated responses, so those combinations are the high-signal findings.

Low risk (``Risk.NO_DANGER``): a small number of benign GETs with one extra
header. Probes the start URL plus a bounded sample of crawled endpoints.
"""
from sitadel.config.settings import Risk
from sitadel.report import Severity
from sitadel.utils.container import Services
from .. import AttackPlugin

# Attacker-controlled origin used to detect reflection.
EVIL_ORIGIN = "https://evil.example"

# Cap on endpoints probed so a large crawl does not turn into a CORS sweep.
_MAX_TARGETS = 25


class Cors(AttackPlugin):
    level = Risk.NO_DANGER

    def _targets(self, start_url, crawled_urls):
        seen = set()
        targets = []
        for url in [start_url, *(crawled_urls or [])]:
            url = str(url)
            if url not in seen:
                seen.add(url)
                targets.append(url)
            if len(targets) >= _MAX_TARGETS:
                break
        return targets

    def _check(self, output, request, url):
        resp = request.send(
            url=url, method="GET", payload=None,
            headers={"Origin": EVIL_ORIGIN},
        )
        if resp is None:
            return
        acao = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip()
        credentials = acac.lower() == "true"
        reflected = acao == EVIL_ORIGIN
        wildcard = acao == "*"
        if not (reflected or wildcard):
            return

        if reflected and credentials:
            output.finding(
                "CORS misconfiguration: reflects an arbitrary Origin with "
                "credentials at %s" % url,
                url=url, plugin="Cors", parameter="Origin",
                severity=Severity.HIGH,
                evidence="Origin: %s -> Access-Control-Allow-Origin: %s, "
                         "Allow-Credentials: true" % (EVIL_ORIGIN, acao),
                finding_type="cors",
            )
        elif reflected:
            output.finding(
                "CORS misconfiguration: reflects an arbitrary Origin at %s" % url,
                url=url, plugin="Cors", parameter="Origin",
                severity=Severity.MEDIUM,
                evidence="Origin: %s -> Access-Control-Allow-Origin: %s"
                         % (EVIL_ORIGIN, acao),
                finding_type="cors",
            )
        elif wildcard and credentials:
            output.finding(
                "CORS misconfiguration: wildcard Access-Control-Allow-Origin "
                "with credentials at %s" % url,
                url=url, plugin="Cors", parameter="Origin",
                severity=Severity.MEDIUM,
                evidence="Access-Control-Allow-Origin: * with "
                         "Allow-Credentials: true",
                finding_type="cors",
            )

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking CORS configuration..")
        for url in self._targets(start_url, crawled_urls):
            try:
                self._check(output, request, url)
            except Exception as e:
                logger.error(e)
                output.debug("CORS check error on %s: %s" % (url, e))
