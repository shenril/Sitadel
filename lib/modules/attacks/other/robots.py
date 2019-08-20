from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Robots(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking robots paths..")
        try:
            url = urljoin(start_url, "robots.txt")
            resp = request.send(url=url, method="GET", payload=None, headers=None)
            for line in str(resp.text).splitlines():
                if line.startswith("Disallow"):
                    disallow_path = line.split(": ")[1].split(" ")[0]
                    check_url = urljoin(start_url, disallow_path)
                    resp = request.send(
                        url=check_url, method="GET", payload=None, headers=None
                    )
                    output.finding(" - [%s] %s" % (resp.status_code, check_url))
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
