from urllib.parse import urljoin

from lib.config.settings import Risk
from lib.utils.container import Services
from .. import AttackPlugin


class Admin(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        datastore = Services.get("datastore")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking admin interfaces...")
        with datastore.open("admin.txt", "r") as db:
            dbfiles = [x.strip() for x in db.readlines()]
            try:
                for adminpath in dbfiles:
                    url = urljoin(str(start_url), str(adminpath))
                    output.debug("Testing: %s" % url)
                    resp = request.send(
                        url=url, method="HEAD", payload=None, headers=None
                    )
                    if resp.status_code == 200:
                        if resp.url == url.replace(" ", "%20"):
                            output.finding("Found admin panel at %s" % resp.url)
            except Exception as e:
                logger.error(e)
                output.error("Error occured\nAborting this attack...\n")
                output.debug("Traceback: %s" % e)
                return
