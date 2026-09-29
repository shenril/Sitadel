"""Exposed sensitive-file discovery — issue #105.

Probes the target origin for well-known sensitive artifacts (VCS metadata,
dotfiles, config backups, key material) from ``data/exposed.txt``. Confirmation
is **content-signature based**, not status-code based, so a site that soft-404s
(returns 200 for everything) does not produce false positives: a file is only
reported when its body matches a known signature, or — for artifacts without a
specific signature — only when the site is shown to serve real 404s and the file
returns distinct 200 content.
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit, urlunsplit

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin

# Per-file content signatures — a match is high-confidence confirmation.
_SIGNATURES = {
    ".git/HEAD": re.compile(r"ref:\s*refs/|^[0-9a-f]{40}\b", re.I | re.M),
    ".git/config": re.compile(r"\[core\]|repositoryformatversion", re.I),
    ".svn/entries": re.compile(r"svn://|dir\b|^\d+$", re.I | re.M),
    ".hg/hgrc": re.compile(r"\[paths\]|default\s*=", re.I),
    ".htpasswd": re.compile(r":\$(?:apr1|2[aby]|6)\$|:[A-Za-z0-9./]{13}$", re.M),
    ".htaccess": re.compile(r"RewriteEngine|<Directory|AuthType", re.I),
    ".DS_Store": re.compile(r"Bud1"),
    "web.config": re.compile(r"<configuration|<connectionStrings", re.I),
    "id_rsa": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    "id_dsa": re.compile(r"-----BEGIN (?:DSA )?PRIVATE KEY-----"),
    ".aws/credentials": re.compile(r"aws_access_key_id|aws_secret_access_key", re.I),
    ".npmrc": re.compile(r"_authToken|registry\s*=", re.I),
    "docker-compose.yml": re.compile(r"^\s*services:", re.I | re.M),
    "composer.lock": re.compile(r'"packages"|"content-hash"', re.I),
    "package-lock.json": re.compile(r'"lockfileVersion"|"dependencies"', re.I),
    "server-status": re.compile(r"Apache Server Status|Server Version", re.I),
}

# .env family: KEY=VALUE lines with credential-ish keys.
_ENV_SIG = re.compile(
    r"(?m)^\s*(?:DB_|APP_|AWS_|SECRET|API|.*_KEY|.*_TOKEN|.*_PASSWORD)\w*\s*=",
    re.I,
)

# SQL dumps / config backups: generic content hints (used only when the site
# serves real 404s — see the baseline logic below).
_GENERIC_HINT = re.compile(
    r"CREATE TABLE|INSERT INTO|DB_PASSWORD|define\(|SQLite format|password",
    re.I,
)


def _signature_for(path):
    name = path.strip().lstrip("/")
    if name in _SIGNATURES:
        return _SIGNATURES[name]
    if name.startswith(".env"):
        return _ENV_SIG
    return None


class Exposure(AttackPlugin):
    level = Risk.NOISY

    def _origin(self, url):
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, "", "", "")) + "/"

    def _soft_404(self, request, origin):
        """(baseline_is_200, baseline_len): does the site 200 a bogus path?"""
        probe = urljoin(origin, "sitadel-not-here-4f3c9a1e")
        resp = request.send(url=probe, method="GET", payload=None, headers=None)
        if resp is None:
            return False, 0
        return resp.status_code == 200, len(resp.text or "")

    def _check(self, output, request, origin, path, soft404, base_len):
        url = urljoin(origin, path.lstrip("/"))
        resp = request.send(url=url, method="GET", payload=None, headers=None)
        if resp is None or resp.status_code != 200:
            return
        body = resp.text or ""
        signature = _signature_for(path)
        if signature is not None:
            if signature.search(body):
                output.finding(
                    "Exposed sensitive file: %s" % url,
                    url=url, plugin="Exposure", parameter=path,
                    evidence="200 with matching content signature",
                    finding_type="exposed_file",
                )
            return
        # No specific signature: only trust a 200 when the site does real 404s
        # (otherwise every path 200s), the body differs from the 404 page, and
        # it carries a plausible sensitive hint.
        if not soft404 and abs(len(body) - base_len) > 32 and _GENERIC_HINT.search(body):
            output.finding(
                "Possibly exposed sensitive file: %s" % url,
                url=url, plugin="Exposure", parameter=path,
                confidence="tentative",
                evidence="200 with distinct content on a site that returns 404s",
                finding_type="exposed_file",
            )

    def _cancelled(self):
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        datastore = Services.get("datastore")
        logger = Services.get("logger")

        output.info("Checking for exposed sensitive files..")
        origin = self._origin(str(start_url))
        soft404, base_len = self._soft_404(request, origin)
        with datastore.open("exposed.txt", "r") as db:
            paths = [x.strip() for x in db if x.strip()]

        def scan(path):
            if self._cancelled():
                return
            try:
                self._check(output, request, origin, path, soft404, base_len)
            except Exception as e:
                logger.error(e)
                output.debug("Exposure error on %s: %s" % (path, e))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan, p) for p in paths]
            try:
                for future in as_completed(futures):
                    if self._cancelled():
                        executor.shutdown(cancel_futures=True)
                        break
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
