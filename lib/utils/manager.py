from lib.config import settings
from lib.modules.attacks import Attacks
from lib.modules.crawler.crawler import crawl
from lib.modules.fingerprints import Fingerprints
from lib.utils.datastore import Datastore
from lib.utils.output import Output


def fingerprints(modules, agent, proxy, redirect, timeout, url, cookie):
    plugins = settings.fingerprint_plugins
    if modules is not None:
        plugins = modules
    Fingerprints(
        agent=agent,
        proxy=proxy,
        redirect=redirect,
        timeout=timeout,
        url=url,
        cookie=cookie
    ).run(plugins)


def crawler(start_url, agent):
    return crawl(start_url, agent)


def attacks(modules, url, crawled_urls):
    plugins = settings.attack_plugins
    if modules is not None:
        plugins = modules
    Attacks(url, crawled_urls).run(plugins)
