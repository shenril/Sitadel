import socket
import subprocess
from urllib.parse import urlparse

from lib.utils.container import Services
from lib.config.settings import Risk
from .. import AttackPlugin


class Anonymous(AttackPlugin):
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        logger = Services.get("logger")

        output.info("Scanning anonymous cipher vuln...")
        ip = ""
        port = "443"
        try:
            ip += socket.gethostbyname(urlparse(start_url).hostname)
            socket.inet_aton(ip)
            r = subprocess.Popen(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    ip + ":" + str(port),
                    "-cipher",
                    "aNULL",
                ],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
            ).communicate()[0]
            if "handshake failure" not in str(r):
                output.finding(
                    "That site is vulnerable to Anonymous Cipher, CVE-2007-1858."
                )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
