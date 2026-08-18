from __future__ import annotations

import base64
import threading

from selectolax.parser import HTMLParser


class Authenticator:
    """Holds authentication state for a scan and applies it to requests.

    Supports HTTP Basic, static Bearer tokens, arbitrary extra headers, and
    form-based login (with optional CSRF-token extraction). Session cookies
    obtained at login live in the shared ``requests.Session`` cookie jar and
    are merged into every subsequent request by :class:`SingleRequest`.
    """

    def __init__(self, headers=None, login_url=None, login_data=None,
                 csrf_field=None, logged_in_check=None):
        self.headers = dict(headers or {})
        self.login_url = login_url
        self.login_data = dict(login_data or {})
        self.csrf_field = csrf_field
        self.logged_in_check = logged_in_check
        self._lock = threading.Lock()

    @classmethod
    def from_options(cls, *, basic=None, bearer=None, headers=None,
                     login_url=None, login_data=None, csrf_field=None,
                     logged_in_check=None):
        """Build an Authenticator from CLI-style options (or None if no auth)."""
        hdrs = {}
        for header in headers or []:
            if ":" in header:
                key, value = header.split(":", 1)
                hdrs[key.strip()] = value.strip()
        if basic:
            token = base64.b64encode(basic.encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"
        if bearer:
            hdrs["Authorization"] = f"Bearer {bearer}"

        data = {}
        if login_data:
            for pair in login_data.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    data[key] = value

        if not (hdrs or login_url):
            return None
        return cls(headers=hdrs, login_url=login_url, login_data=data,
                   csrf_field=csrf_field, logged_in_check=logged_in_check)

    @property
    def has_login(self):
        return bool(self.login_url)

    def _extract_csrf(self, session, verify, timeout):
        """GET the login page and pull the hidden CSRF token, if configured."""
        if not self.csrf_field:
            return {}
        try:
            resp = session.get(self.login_url, verify=verify, timeout=timeout)
        except Exception:
            return {}
        node = HTMLParser(resp.text).css_first(
            f'input[name="{self.csrf_field}"]'
        )
        if node is not None:
            return {self.csrf_field: node.attributes.get("value", "") or ""}
        return {}

    def login(self, session, verify=False, timeout=None):
        """Perform the form login through the session (stores cookies)."""
        if not self.has_login:
            return None
        # Serialize concurrent logins (the attack phase is multi-threaded).
        with self._lock:
            data = dict(self.login_data)
            data.update(self._extract_csrf(session, verify, timeout))
            try:
                return session.post(
                    self.login_url, data=data, verify=verify,
                    timeout=timeout, allow_redirects=True,
                )
            except Exception:
                return None

    def looks_logged_out(self, resp):
        """True when a response suggests the session is no longer valid."""
        if resp is None or not (self.has_login and self.logged_in_check):
            return False
        return self.logged_in_check not in resp.text
