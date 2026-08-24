from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urljoin, urlsplit

import aiohttp
from requests.utils import dict_from_cookiejar
from selectolax.parser import HTMLParser

from sitadel.config import settings
from sitadel.utils.container import Services
from sitadel.utils.events import PageDiscovered


def _publish(event) -> None:
    """Publish to the event bus if one is registered (TUI mode); else no-op."""
    try:
        bus = Services.get("events")
    except NameError:
        return
    bus.publish(event)

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
                    if len(results) > max_pages:
                        continue
                    html = await _fetch(session, url, timeout)
                    if html is None or depth >= max_depth:
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

    return sorted(results)


def crawl(url, user_agent):
    output = Services.get("output")
    output.info("Start crawling the target website")
    return asyncio.run(_crawl(str(url), user_agent, _config()))
