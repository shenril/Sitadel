"""Server-Side Template Injection (SSTI) — issue #72.

Injects arithmetic polyglots for the common template engines and detects the
*evaluated* result. Factors are randomized per scan so the expected product is a
value unlikely to occur naturally in the page — the payload literal (``a*b``)
being reflected is not enough; only the computed product counts, which kills the
classic ``{{7*7}} -> 49`` false positive.

Reuses ``AttackPlugin.run_injection`` like the other injection plugins.
"""
import random
import re

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin

# Polyglot templates per engine family; ``AA``/``BB`` are replaced by the
# per-scan random factors. Covers Jinja2/Twig, JSP-EL/Freemarker,
# Ruby/Thymeleaf, ERB, bare brace, and a nested variant.
_TEMPLATES = (
    "{{AA*BB}}",
    "${AA*BB}",
    "#{AA*BB}",
    "<%= AA*BB %>",
    "{AA*BB}",
    "${{AA*BB}}",
)

# Extract the two factors from a payload so the detector can recompute the
# expected product without carrying extra state.
_FACTORS = re.compile(r"(\d{2,4})\*(\d{2,4})")


class Ssti(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        m = _FACTORS.search(payload)
        if not m:
            return None
        a, b = int(m.group(1)), int(m.group(2))
        product = str(a * b)
        # Evaluated: the product appears and the literal expression does not
        # (a page merely reflecting the payload shows "a*b", not the product).
        if product in resp.text and ("%d*%d" % (a, b)) not in resp.text:
            return "Server-Side Template Injection"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking server-side template injection...")
        a = random.randint(1000, 9999)
        b = random.randint(1000, 9999)
        payloads = [
            t.replace("AA", str(a)).replace("BB", str(b)) for t in _TEMPLATES
        ]
        self.run_injection(payloads, crawled_urls, self.detect)
