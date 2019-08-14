from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor as PoolExecutor

from lib.config.settings import Risk
from lib.utils.container import Services
from .. import AttackPlugin


class Admin(AttackPlugin):
    output = Services.get("output")
    datastore = Services.get("datastore")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def check_url(self, url):
        try:
            resp = self.request.send(url=url, method="HEAD", payload=None, headers=None)
            if resp.status_code == 200:
                if resp.url == url.replace(" ", "%20"):
                    self.output.finding("Found admin panel at %s" % resp.url)
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking admin interfaces...")
        with self.datastore.open("admin.txt", "r") as db:
            dbfiles = [x.strip() for x in db.readlines()]
            urls = map(
                lambda adminpath: urljoin(str(start_url), str(adminpath)), dbfiles
            )
            with PoolExecutor(max_workers=4) as executor:
                for _ in executor.map(self.check_url, urls):
                    pass
