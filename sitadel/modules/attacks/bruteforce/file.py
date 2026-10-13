from urllib.parse import urljoin
from sitadel.utils.container import Services
from .. import AttackPlugin


class File(AttackPlugin):
    output = Services.get("output")
    datastore = Services.get("datastore")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def check_url(self, url):
        try:
            self.output.debug("Testing: %s" % url)
            resp = self.request.send(url=url, method="HEAD", payload=None, headers=None)
            if resp.status_code == 200:
                if resp.url == url.replace(" ", "%20"):
                    self.output.finding("Found file at %s" % resp.url)
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking common files...")
        with self.datastore.open("cfile.txt", "r") as db:
            dbfiles = [x.strip() for x in db.readlines()]
            urls = map(lambda filex: urljoin(str(start_url), str(filex)), dbfiles)
            # Bounded thread pool so the wordlist is probed concurrently.
            self.run_pool(urls, self.check_url)

