#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
# @name:    Sitadel - Web Application Security Scanner
# @repo:    https://github.com/shenril/Sitadel
# @author:  Shenril
# @license: See the file 'LICENSE.txt'

import argparse
import logging
import sys
import signal
from lib import __version__
from lib.config import settings
from lib.config.settings import Risk
from lib.request.request import SingleRequest
from lib.utils import banner, manager, output, validator
from lib.utils.container import Services
from lib.utils.datastore import Datastore
from lib.utils.output import Output


class Sitadel(object):
    bn = banner.Banner()
    ma = manager
    url = None

    def main(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            usage=self.bn.banner(),
        )
        # Prepare the possible values for risk levels
        risk_values = [r.value for r in Risk]
        # Add arguments
        parser.add_argument("url", help="URL of the website to scan")
        parser.add_argument(
            "-r",
            "--risk",
            type=int,
            help="Level of risk allowed for the scan",
            choices=risk_values,
        )
        parser.add_argument(
            "-ua",
            "--user-agent",
            default="Sitadel " + __version__,
            help="User-agent to set for the scan requests",
        )
        parser.add_argument(
            "--redirect",
            dest="redirect",
            help="Whether or not the scan should follow redirection",
            action="store_true",
        )
        parser.add_argument(
            "--no-redirect",
            dest="redirect",
            help="Whether or not the scan should follow redirection",
            action="store_false",
        )
        parser.set_defaults(redirect=True)
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=30,
            help="Timeout to set for the scan HTTP requests",
        )
        parser.add_argument(
            "-c", "--cookie", help="Cookie to set for the scan HTTP requests"
        )
        parser.add_argument(
            "-p", "--proxy", help="Proxy to set for the scan HTTP requests"
        )
        parser.add_argument(
            "-f", "--fingerprint", nargs="+", help="Fingerprint modules to activate"
        )
        parser.add_argument(
            "-a", "--attack", nargs="+", help="Attack modules to activate"
        )
        parser.add_argument(
            "--config", help="Path to the config file", default="config/config.yml"
        )
        parser.add_argument(
            "-v",
            "--verbosity",
            action="count",
            default=0,
            help="Increase output verbosity",
        )
        parser.add_argument("--version", action="version", version=self.bn.version())
        args = parser.parse_args()

        # Verify the target URL
        self.url = validator.validate_target(args.url)

        # Reading configuration
        settings.from_yaml(args.config)
        if args.risk is not None:
            settings.risk = Risk(args.risk)

        # Setting up the logger
        logger = logging.getLogger("sitadelLog")
        logging.basicConfig(
            filename="sitadel.log",
            filemode="w",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%d-%b-%y %H:%M:%S",
            level=(logging.CRITICAL - (args.verbosity * 10)),
        )

        # Create handlers
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)

        file_handler = logging.FileHandler("sitadel.log")
        file_handler.setLevel(level=(logging.CRITICAL - (args.verbosity * 10)))

        # Create formatters and add it to handlers
        console_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(console_format)

        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_format)

        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        # Register services
        Services.register("datastore", Datastore(settings.datastore))
        Services.register("logger", logger)
        Services.register("output", Output())
        Services.register(
            "request_factory",
            SingleRequest(
                url=self.url,
                agent=args.user_agent,
                proxy=args.proxy,
                redirect=args.redirect,
                timeout=args.timeout,
            ),
        )

        # Display target and scan starting time
        self.bn.preamble(self.url)
        try:
            # Run the fingerprint modules
            self.ma.fingerprints(
                args.fingerprint,
                self.url,
                args.cookie,
            )

            # Run the crawler to discover urls
            discovered_urls = self.ma.crawler(self.url, args.user_agent)

            # Hotfix on KeyboardInterrupt being redirected to scrapy crawler process
            signal.signal(signal.SIGINT, signal.default_int_handler)

            # Run the attack modules on discovered urls
            self.ma.attacks(args.attack, self.url, discovered_urls)
        except KeyboardInterrupt:
            raise
        finally:
            self.bn.postscript()


if __name__ == "__main__":
    try:
        Sitadel().main()
    except KeyboardInterrupt:
        sys.exit(output.Output().error("Interruption by the user, Quitting..."))
