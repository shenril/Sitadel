import importlib
import os
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import IPlugin
from .targets import Target, taint_body, taint_target, taint_url

__all__ = ["AttackPlugin", "Attacks", "Target", "taint_body", "taint_target"]


class AttackPlugin(metaclass=IPlugin):
    # Default risk level for attack modules is NOISY since it sends requests
    level = Risk.NOISY

    # Optional profile requirements, e.g. {"lang": "php"}. Empty means the
    # attack applies to any target.
    requires: dict = {}

    def applies_to(self, profile):
        """Whether this attack is relevant given the fingerprint profile.

        Fail-open: an attack is skipped only when the profile *positively*
        contradicts a requirement (e.g. it requires PHP but a different
        language was detected). When the relevant signal is unknown, the
        attack still runs, so gating never hides a real vulnerability just
        because fingerprinting missed the stack.
        """
        if profile is None:
            return True
        for key, expected in self.requires.items():
            detected = profile.get(key)
            if detected is None:
                continue
            if str(expected).lower() not in detected.lower():
                return False
        return True

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

    # ``taint_url`` stays available for any plugin still working URL-first; the
    # implementation now lives in ``targets`` alongside the body taints.
    taint_url = staticmethod(taint_url)

    @staticmethod
    def build_targets(crawled_urls):
        """Assemble the injectable targets for this scan.

        Every crawled URL becomes a GET query-string target (URLs without
        parameters are skipped later by ``taint_target``), and any API targets
        discovered by the discovery step (registered under ``api_targets``) are
        appended so body injection reaches JSON/XML endpoints too.
        """
        targets = [Target(url=url) for url in (crawled_urls or [])]
        try:
            api_targets = Services.get("api_targets")
        except NameError:
            api_targets = None
        if api_targets:
            targets.extend(api_targets)
        return targets

    def run_injection(self, payloads, crawled_urls, detector, workers=20):
        """Test ``payloads`` against every injectable target with one pool.

        ``detector(response, payload)`` returns a human label when the response
        indicates the injection worked (e.g. ``"MySQL Injection"``), or a falsy
        value otherwise. The response signature is identical across GET query
        and JSON/XML/form body targets, so a module writes its detection once
        and it runs against every surface.
        """
        output = Services.get("output")
        logger = Services.get("logger")
        request = Services.get("request_factory")
        targets = self.build_targets(crawled_urls)

        def probe(payload, target):
            try:
                kwargs = taint_target(target, payload)
                if kwargs is None:
                    return
                output.debug("Testing: %s" % target.describe())
                resp = request.send(**kwargs)
                if resp is None:
                    return
                label = detector(resp, payload)
                if label:
                    output.finding(
                        "That site may be vulnerable to %s at %s\nInjection: %s"
                        % (label, target.describe(), payload),
                        url=kwargs["url"],
                        plugin=type(self).__name__,
                    )
            except Exception as err:
                logger.error(err)
                output.debug("Injection error: %s" % err)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(probe, payload, target)
                for payload in payloads
                for target in targets
            ]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise

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

        # Consult the fingerprint profile (if any) to skip attack classes that
        # do not apply to the detected stack.
        try:
            profile = Services.get("profile")
        except NameError:
            profile = None

        try:
            selected = []
            for plugin in AttackPlugin.enabled():
                instance = plugin()
                if instance.applies_to(profile):
                    selected.append(instance)
                else:
                    self.output.info(
                        "Skipping {name} (not applicable to target)".format(
                            name=instance.__class__.__name__
                        )
                    )
            attacks = [
                (instance, instance.process(self.start_url, self.crawled_urls))
                for instance in selected
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
