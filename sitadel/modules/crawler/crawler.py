from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import aiohttp
from requests.utils import dict_from_cookiejar
from selectolax.parser import HTMLParser

from sitadel.config import settings
from sitadel.modules.attacks.targets import Target
from sitadel.utils.container import Services
from sitadel.utils.events import PageDiscovered


def _publish(event) -> None:
    """Publish to the event bus if one is registered (TUI mode); else no-op."""
    try:
        bus = Services.get("events")
    except NameError:
        return
    bus.publish(event)


def _cancelled() -> bool:
    """Whether the user asked to stop the scan (TUI quit); else False."""
    try:
        return Services.get("cancel").is_set()
    except NameError:
        return False

# Default crawl bounds; overridable through the optional `crawler:` config block.
_DEFAULTS = {
    "max_depth": 3,
    "max_pages": 500,
    "concurrency": 20,
    "timeout": 15,
    "ignore_params": [],
}


def _config() -> dict:
    cfg = dict(_DEFAULTS)
    cfg.update(getattr(settings, "crawler", None) or {})
    return cfg


def _auth_context():
    """Auth headers + cookies to crawl as the authenticated user.

    Read from the shared ``request_factory`` (populated by the login flow in
    ``Authenticator``) so the crawler discovers pages behind login. Returns two
    empty dicts when no request factory / authentication is configured, so
    unauthenticated scans and direct ``crawl()`` calls are unaffected.
    """
    headers, cookies = {}, {}
    try:
        request = Services.get("request_factory")
    except Exception:
        return headers, cookies
    authenticator = getattr(request, "authenticator", None)
    if authenticator is not None:
        headers.update(authenticator.headers)
    session = getattr(request, "session", None)
    if session is not None:
        cookies.update(dict_from_cookiejar(session.cookies))
    return headers, cookies


def url_signature(url: str, ignore_params=()) -> tuple:
    """Signature that collapses URLs differing only in query-parameter *values*.

    Two URLs sharing scheme, host, path and the same set of parameter *names* map to
    the same signature, so ``?id=1`` and ``?id=2`` are one endpoint shape. This is what
    keeps parameter permutations from exploding the crawl frontier, while still keeping a
    representative (parameterized) URL per shape for the attack phase to inject into.
    """
    parts = urlsplit(url)
    keys = tuple(
        sorted(
            key
            for key, _ in parse_qsl(parts.query, keep_blank_values=True)
            if key not in ignore_params
        )
    )
    return (parts.scheme.lower(), parts.netloc.lower(), parts.path, keys)


def _extract_links(base_url: str, html: str) -> list[str]:
    tree = HTMLParser(html)
    base = base_url
    base_node = tree.css_first("base[href]")
    if base_node is not None:
        base = urljoin(base_url, base_node.attributes.get("href") or "")

    links = []
    for node in tree.css("a[href]"):
        href = node.attributes.get("href")
        if not href:
            continue
        absolute = urljoin(base, href)
        if urlsplit(absolute).scheme not in ("http", "https"):
            continue
        links.append(absolute.split("#", 1)[0])  # drop fragment
    return links


# Input types that submit no user-controllable value (never injectable).
_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset"}


def _extract_forms(base_url: str, html: str, host: str) -> list[Target]:
    """Turn each same-host ``<form>`` into an injectable :class:`Target`.

    User-controllable fields become tainted ``params``; hidden fields (incl.
    CSRF tokens) become ``fixed`` (sent verbatim). GET forms bake the field
    names into the query so the shared ``taint_url`` path handles them; POST
    forms become url-encoded body targets. Multipart / file-upload forms are
    skipped for now (the body encoder has no multipart support).
    """
    tree = HTMLParser(html)
    base = base_url
    base_node = tree.css_first("base[href]")
    if base_node is not None:
        base = urljoin(base_url, base_node.attributes.get("href") or "")

    targets: list[Target] = []
    for form in tree.css("form"):
        action = urljoin(base, (form.attributes.get("action") or "").strip())
        action = action.split("#", 1)[0]
        parts = urlsplit(action)
        if parts.scheme not in ("http", "https") or parts.hostname != host:
            continue
        method = (form.attributes.get("method") or "GET").strip().upper()
        enctype = (form.attributes.get("enctype") or "").lower()

        injectable: dict = {}
        fixed: dict = {}
        has_file = False
        for node in form.css("input[name], textarea[name], select[name]"):
            name = node.attributes.get("name")
            if not name:
                continue
            if node.tag == "input":
                itype = (node.attributes.get("type") or "text").strip().lower()
            else:
                itype = node.tag  # "textarea" / "select"
            if itype in _SKIP_INPUT_TYPES:
                continue
            if itype == "file":
                has_file = True
                continue
            value = node.attributes.get("value") or ""
            if itype == "hidden":
                fixed[name] = value
            else:
                injectable[name] = value

        # v1: multipart / file-upload forms are out of scope.
        if has_file or "multipart" in enctype:
            continue
        # Nothing user-controllable to inject into.
        if not injectable:
            continue

        if method == "POST":
            targets.append(Target(
                url=action, method="POST", body_format="form",
                params=injectable, fixed=fixed,
            ))
        else:
            # GET form: fields live in the query string; taint_url skips the
            # fixed keys, so hidden values ride along untainted.
            query = {**{name: "" for name in injectable}, **fixed}
            url = action + ("?" + urlencode(query) if query else "")
            targets.append(Target(
                url=url, method="GET", params=injectable, fixed=fixed,
            ))
    return targets


def form_signature(target: Target) -> tuple:
    """Collapse forms sharing action + method + field names to one representative."""
    parts = urlsplit(target.url)
    names = tuple(sorted(list(target.params) + list(target.fixed)))
    return (parts.scheme.lower(), parts.netloc.lower(), parts.path,
            target.method, target.body_format, names)


async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int) -> str | None:
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            ctype = resp.headers.get("Content-Type", "").lower()
            if resp.status != 200 or "html" not in ctype:
                return None
            raw = await resp.read()
            return raw.decode(resp.charset or "utf-8", errors="ignore")
    except Exception:
        # A single failing request must never abort the crawl.
        return None


async def _crawl(start_url: str, user_agent: str, cfg: dict) -> list[str]:
    host = urlsplit(start_url).hostname
    ignore = tuple(cfg["ignore_params"])
    max_depth = cfg["max_depth"]
    max_pages = cfg["max_pages"]
    concurrency = cfg["concurrency"]
    timeout = cfg["timeout"]

    seen = {url_signature(start_url, ignore)}
    results = {start_url}
    # Discovered HTML forms, de-duplicated by their shape (see form_signature).
    forms: list[Target] = []
    form_seen: set = set()
    _publish(PageDiscovered(start_url))
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait((start_url, 0))

    connector = aiohttp.TCPConnector(
        limit=concurrency, limit_per_host=concurrency, ssl=False
    )
    # Crawl as the authenticated user (same-domain restriction below keeps the
    # cookies scoped to the target host).
    extra_headers, cookies = _auth_context()
    headers = {"User-Agent": user_agent, **extra_headers}

    async with aiohttp.ClientSession(
        connector=connector, headers=headers, cookies=cookies
    ) as session:

        async def worker():
            while True:
                url, depth = await queue.get()
                try:
                    # Fast-drain the frontier on cancel so queue.join() returns.
                    if _cancelled() or len(results) > max_pages:
                        continue
                    html = await _fetch(session, url, timeout)
                    if html is None:
                        continue
                    # Collect forms on every fetched page (leaves included), so
                    # a form at max depth is still discovered.
                    for target in _extract_forms(url, html, host):
                        sig = form_signature(target)
                        if sig in form_seen:
                            continue
                        form_seen.add(sig)
                        forms.append(target)
                        _publish(PageDiscovered(target.url, is_form=True))
                    if depth >= max_depth:
                        continue
                    for link in _extract_links(url, html):
                        if urlsplit(link).hostname != host:
                            continue
                        sig = url_signature(link, ignore)
                        if sig in seen:
                            continue
                        seen.add(sig)
                        # Cap the number of discovered pages. No await between the
                        # check and the add, so this stays consistent across workers.
                        if len(results) >= max_pages:
                            continue
                        results.add(link)
                        _publish(PageDiscovered(link))
                        queue.put_nowait((link, depth + 1))
                except Exception:
                    pass
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await queue.join()
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    return sorted(results), forms


def crawl(url, user_agent):
    output = Services.get("output")
    output.info("Start crawling the target website")
    urls, form_targets = asyncio.run(_crawl(str(url), user_agent, _config()))
    # Register discovered forms as injectable targets, mirroring how API
    # discovery registers ``api_targets``; ``build_targets`` extends with them.
    # The public return stays ``list[str]`` so existing callers are unaffected.
    if form_targets:
        Services.register("form_targets", form_targets)
        output.info(
            "Crawler discovered %d HTML form target(s)" % len(form_targets)
        )
    return urls
