"""Path traversal / Local File Inclusion (LFI) — issue #72.

Injects directory-traversal sequences targeting well-known files and detects
their signatures in the response (``/etc/passwd`` line format, Windows
``win.ini``/``boot.ini`` sections). Reuses ``AttackPlugin.run_injection`` like
the other injection plugins; payloads live in ``data/traversal.txt``.
"""
from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin
from ._signatures import FILE_DISCLOSURE


class Traversal(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        if FILE_DISCLOSURE.search(resp.text):
            return "Path Traversal / LFI"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking path traversal / LFI...")
        with self.datastore.open("traversal.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db if x.strip()]
        self.run_injection(payloads, crawled_urls, self.detect)
