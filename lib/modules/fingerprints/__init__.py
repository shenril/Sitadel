import importlib
import os
import pkgutil

from lib.config.settings import Risk
from lib.utils.container import Services
from .. import IPlugin


class FingerprintPlugin(metaclass=IPlugin):
    # Default risk level for fingerprint module is NO DANGER since it only analyze one request response
    level = Risk.NO_DANGER

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

            # Pass the result over the fingerprint module for processing
            fingerprints = [
                (p(), p().process(resp.headers, resp.text))
                for p in FingerprintPlugin.plugins
            ]

            # Display findings for each category of modules
            for category, result in fingerprints:
                if result is not None:
                    self.output.finding(
                        "{category} detected: {result}".format(
                            category=category, result=result
                        )
                    )

        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting fingerprint...\n")
            return
