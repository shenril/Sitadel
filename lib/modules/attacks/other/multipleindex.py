from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class MultipleIndex(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        datastore = Services.get("datastore")
        logger = Services.get("logger")

        output.info("Checking multiple index..")
        db = datastore.open("index.txt", "r")
        dbfiles = [x.split("\n") for x in db]
        try:
            for d in dbfiles:
                url = urljoin(start_url, str(d[0]))
                resp = request.send(url=url, method="GET", payload=None, headers=None)
                if resp.status_code == 200:
                    if resp.url == url.replace(" ", "%20"):
                        output.finding("Found Index Page at %s" % (resp.url))
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
