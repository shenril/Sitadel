"""Path traversal / Local File Inclusion (LFI) — issue #72.

Injects directory-traversal sequences targeting well-known files and detects
their signatures in the response (``/etc/passwd`` line format, Windows
``win.ini``/``boot.ini`` sections). Reuses ``AttackPlugin.run_injection`` like
the other injection plugins; payloads live in ``data/traversal.txt``.
"""
import re

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin

# Signatures of the files the payloads try to read. Compiled once — the detector
# runs on every response (per payload x target).
_LFI = re.compile(
    r"root:.*:0:0:"                 # /etc/passwd
    r"|\[boot loader\]"             # boot.ini
    r"|\[fonts\]|\[extensions\]"    # win.ini
    r"|for 16-bit app support",     # win.ini
    re.I,
)


class Traversal(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        if _LFI.search(resp.text):
            return "Path Traversal / LFI"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking path traversal / LFI...")
        with self.datastore.open("traversal.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db if x.strip()]
        self.run_injection(payloads, crawled_urls, self.detect)
