import importlib
import os
import pkgutil

from lib.config import settings
from lib.config.settings import Risk
from lib.utils.container import Services
from .. import IPlugin


class FingerprintPlugin(metaclass=IPlugin):
    # Default risk level for fingerprint module is NO DANGER since it only analyze one request response
    level = Risk.NO_DANGER

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

    def process(self, headers, content):
        raise NotImplementedError(str(self) + ": Process method not found")

    def __repr__(self):
        parent_module = self.__class__.__module__.split(".")[-2]
        return parent_module.title()


class Fingerprints:
    def __init__(self, url, cookie):
        self.url = url
        self.cookie = cookie
        self.output = Services.get("output")
        self.logger = Services.get("logger")
        self.request = Services.get("request_factory")

    def run(self, plugins_activated):
        self.output.info("Launching fingerprints modules...")
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
            # Send the recon request
            resp = self.request.send(
                url=self.url,
                method="GET",
                payload=None,
                headers=None,
                cookies=self.cookie,
            )

            # The request layer returns None when the target could not be
            # reached; abort the fingerprint phase cleanly instead of crashing.
            if resp is None:
                self.output.error(
                    "No response from the target\nAborting fingerprint...\n"
                )
                return

            # Pass the result over the fingerprint module for processing
            fingerprints = [
                (p(), p().process(resp.headers, resp.text))
                for p in FingerprintPlugin.enabled()
            ]

            # Aggregate detections into the shared TargetProfile (if registered)
            # so the attack phase can decide which classes are worth launching.
            try:
                profile = Services.get("profile")
            except NameError:
                profile = None

            # Display findings for each category of modules
            for category, result in fingerprints:
                if result is not None:
                    self.output.finding(
                        "{category} detected: {result}".format(
                            category=category, result=result
                        )
                    )
                    # `category` is the plugin's package name (lang, server, …).
                    if profile is not None:
                        profile.add(str(category), result)

        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting fingerprint...\n")
            return
