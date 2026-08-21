#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
# @name:    Sitadel - Web Application Security Scanner
# @repo:    https://github.com/shenril/Sitadel
# @author:  Shenril
# @license: See the file 'LICENSE.txt'

import argparse
import sys
import signal
from sitadel import __version__
from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.request.request import SingleRequest
from sitadel.utils import banner, manager, output, validator
from sitadel.utils.container import Services
from sitadel.model import TargetProfile
from sitadel.report import Findings, write_report
from sitadel.request.auth import Authenticator
from sitadel.utils.datastore import Datastore
from sitadel.utils.logs import setup_logging
from sitadel.utils.output import Output


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
            default=f"Sitadel {__version__}",
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
            "--random-agent",
            dest="random_agent",
            action="store_true",
            help="Use a random User-Agent for each scan request",
        )
        parser.add_argument(
            "--verify",
            dest="verify",
            action="store_true",
            help="Verify the server's TLS certificate (off by default)",
        )
        # Authentication options
        parser.add_argument(
            "--auth-basic", help="HTTP Basic credentials as user:password"
        )
        parser.add_argument(
            "--auth-bearer", help="Bearer token to send in the Authorization header"
        )
        parser.add_argument(
            "-H",
            "--header",
            dest="headers",
            action="append",
            help="Extra header 'Name: Value' (repeatable), e.g. an API key",
        )
        parser.add_argument(
            "--login-url", help="URL to POST credentials to for form login"
        )
        parser.add_argument(
            "--login-data",
            help="Form login body, e.g. 'username=admin&password=secret'",
        )
        parser.add_argument(
            "--csrf-field",
            help="Name of a hidden CSRF field to read from the login page",
        )
        parser.add_argument(
            "--logged-in-check",
            help="String expected on authenticated pages (drives re-auth)",
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
            "-o", "--output", help="Path to write the findings report to"
        )
        parser.add_argument(
            "--format",
            dest="report_format",
            choices=["stdout", "json", "html", "sarif"],
            default="stdout",
            help="Report format for the findings (default: stdout only)",
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
        logger = setup_logging(args.verbosity)

        # Register services
        Services.register("datastore", Datastore(settings.datastore))
        Services.register("logger", logger)
        Services.register("output", Output(args.verbosity))
        Services.register("findings", Findings())
        Services.register("profile", TargetProfile())
        Services.register(
            "request_factory",
            SingleRequest(
                url=self.url,
                agent=args.user_agent,
                proxy=args.proxy,
                redirect=args.redirect,
                timeout=args.timeout,
                random_agent=args.random_agent,
                verify=args.verify,
            ),
        )

        # Configure authentication (if any) and log in before scanning so all
        # phases run as an authenticated user.
        authenticator = Authenticator.from_options(
            basic=args.auth_basic,
            bearer=args.auth_bearer,
            headers=args.headers,
            login_url=args.login_url,
            login_data=args.login_data,
            csrf_field=args.csrf_field,
            logged_in_check=args.logged_in_check,
        )
        if authenticator is not None:
            request_factory = Services.get("request_factory")
            request_factory.set_authenticator(authenticator)
            if authenticator.has_login:
                request_factory.login()
                probe = request_factory.send(url=self.url, method="GET")
                if authenticator.looks_logged_out(probe):
                    Services.get("output").error(
                        "Login may have failed: the 'logged-in' check did not "
                        "match after authenticating."
                    )
                else:
                    Services.get("output").info("Authenticated to the target.")

        # Display target and scan starting time
        self.bn.preamble(self.url)
        try:
            # Run the fingerprint modules
            self.ma.fingerprints(
                args.fingerprint,
                self.url,
                args.cookie,
            )

            # Show the assembled target profile that will drive attack selection
            profile = Services.get("profile")
            if profile.technologies:
                Services.get("output").info(f"Target profile: {profile.summary()}")

            # Run the crawler to discover urls
            discovered_urls = self.ma.crawler(self.url, args.user_agent)

            # Record the crawl surface. The count goes to console + file; the
            # full list is file-only (-v) so the log lets you review every path
            # discovered before any attack is launched, without flooding stdout.
            output_svc = Services.get("output")
            output_svc.info(
                f"Crawler discovered {len(discovered_urls)} URL(s)"
            )
            for discovered in discovered_urls:
                output_svc.trace(f"Crawled URL: {discovered}")

            # Hotfix on KeyboardInterrupt being redirected to scrapy crawler process
            signal.signal(signal.SIGINT, signal.default_int_handler)

            # Run the attack modules on discovered urls
            self.ma.attacks(args.attack, self.url, discovered_urls)
        except KeyboardInterrupt:
            raise
        finally:
            # Write the findings report (console findings are printed live by
            # Output.finding regardless of the chosen format).
            if args.report_format != "stdout":
                findings = Services.get("findings").all()
                path = args.output or f"sitadel-report.{args.report_format}"
                write_report(findings, args.report_format, path)
                Services.get("output").info(
                    f"Wrote {len(findings)} finding(s) to {path}"
                )
            self.bn.postscript()


def main():
    """Console entry point (see ``[project.scripts]`` in pyproject.toml)."""
    try:
        Sitadel().main()
    except KeyboardInterrupt:
        sys.exit(output.Output().error("Interruption by the user, Quitting..."))


if __name__ == "__main__":
    main()
