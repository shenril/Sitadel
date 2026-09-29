"""Passive secret/credential leak scanner — issue #105.

Scans response bodies for high-confidence secrets (cloud keys, tokens, private
keys). Reads the page bodies the crawler already fetched (registered under the
``page_bodies`` service key) so no page is re-fetched; when that cache is absent
(e.g. a direct call), it falls back to fetching the start URL and crawled URLs.

Passive and low-risk (``Risk.NO_DANGER``): it only reads content already served.
Matched secrets are redacted in the evidence so the report never stores the raw
credential.
"""
import re

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin

# (label, pattern, firm?) — firm matches are high-precision; the rest are
# marked tentative because they can legitimately appear in page content.
_SECRETS = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), True),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), True),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), True),
    ("Stripe live secret key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), True),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), True),
    ("Google OAuth client secret", re.compile(r"GOCSPX-[0-9A-Za-z_\-]{20,}"), True),
    ("Private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), True),
    ("JSON Web Token", re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), False),
    ("Hardcoded secret assignment", re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|passwd|password)"""
        r"""\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"""), False),
]


def _redact(match: str) -> str:
    """Show only the first/last few characters so the report leaks nothing."""
    match = match.strip()
    if len(match) <= 12:
        return match[:2] + "***"
    return "%s...%s" % (match[:6], match[-4:])


class Secrets(AttackPlugin):
    level = Risk.NO_DANGER

    def _bodies(self, start_url, crawled_urls):
        """Prefer the crawler's cached bodies; else fetch (bounded)."""
        try:
            cached = Services.get("page_bodies")
        except NameError:
            cached = None
        if cached:
            return cached
        # Fallback: fetch start URL + crawled URLs (bounded) ourselves.
        request = Services.get("request_factory")
        urls = [str(start_url)] + [str(u) for u in (crawled_urls or [])]
        bodies = {}
        for url in urls[:100]:
            resp = request.send(url=url, method="GET", payload=None, headers=None)
            if resp is not None and resp.text:
                bodies[url] = resp.text
        return bodies

    def _scan(self, output, url, body):
        for label, pattern, firm in _SECRETS:
            m = pattern.search(body)
            if not m:
                continue
            output.finding(
                "Secret leaked in response (%s) at %s" % (label, url),
                url=url, plugin="Secrets", parameter=label,
                confidence="firm" if firm else "tentative",
                evidence="matched %s: %s" % (label, _redact(m.group(0))),
                finding_type="secret_leak",
            )

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        logger = Services.get("logger")

        output.info("Scanning responses for leaked secrets..")
        try:
            bodies = self._bodies(start_url, crawled_urls)
        except Exception as e:
            logger.error(e)
            return
        for url, body in bodies.items():
            if self._cancelled():
                break
            try:
                self._scan(output, url, body)
            except Exception as e:
                logger.error(e)
                output.debug("Secret-scan error on %s: %s" % (url, e))

    @staticmethod
    def _cancelled():
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False
