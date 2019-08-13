from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Listing(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking listing..")
        try:
            url = urljoin(start_url, ".listing")
            resp = request.send(url=url, method="GET", payload=None, headers=None)
            if resp.status_code == 200:
                if resp.url == url.replace(" ", "%20"):
                    output.finding(
                        'Indexing enabled with ".listing" file at %s' % (resp.url)
                    )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
