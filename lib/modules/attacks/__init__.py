import importlib
import os
import pkgutil
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from lib.config import settings
from lib.config.settings import Risk
from lib.utils.container import Services
from .. import IPlugin


class AttackPlugin(metaclass=IPlugin):
    # Default risk level for attack modules is NOISY since it sends requests
    level = Risk.NOISY

    @classmethod
    def enabled(cls):
        """Registered plugins whose risk level is within the configured risk.

        Filtering is done here, at run time, so changing the risk level (or
        loading the configuration after the plugins were imported) always
        takes effect instead of depending on import ordering.
        """
        return [
            plugin
            for plugin in cls.plugins
            if getattr(plugin, "level", Risk.NO_DANGER) <= settings.risk
        ]

    @staticmethod
    def taint_url(url, payload):
        """Rebuild ``url`` with every query parameter value replaced by ``payload``.

        Returns the tainted URL, or ``None`` when the URL has no query
        parameters to inject into. The query string is reassembled with
        ``urlunsplit`` so the separators (``?`` and ``&``) are preserved,
        instead of blindly concatenating onto the original URL.
        """
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query))
        if not params:
            return None
        tainted = {name: payload for name in params}
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
        )

    def process(self, start_url, crawled_urls):
        raise NotImplementedError(str(self) + ": Process method not found")

    def __repr__(self):
        parent_module = self.__class__.__module__.split(".")[-2]
        return parent_module.title()


class Attacks:
    def __init__(self, start_url, crawled_urls):
        self.output = Services.get("output")
        self.logger = Services.get("logger")
        self.start_url = start_url
        self.crawled_urls = crawled_urls

    def run(self, plugins_activated):
        self.output.info("Launching attacks modules...")
        # Register the plugins from configuration
        for p in plugins_activated:
            currentdir = os.path.dirname(os.path.realpath(__file__))
            pkgpath = os.path.dirname(currentdir + "/%s/" % p)
            modules = [name for _, name, _ in pkgutil.iter_modules([pkgpath])]
            for module in modules:
                importlib.import_module(
                    ".{pkg}.{mod}".format(pkg=p, mod=module), __package__
                )

        try:
            attacks = [
                (p(), p().process(self.start_url, self.crawled_urls))
                for p in AttackPlugin.enabled()
            ]
            for category, result in attacks:
                if result is not None:
                    self.output.finding(
                        "{category} detected: {result}".format(
                            category=category, result=result
                        )
                    )

        except Exception as e:
            self.logger.error(e)
            raise e
