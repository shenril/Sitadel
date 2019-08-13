from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Bfile(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        datastore = Services.get("datastore")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking common backup files..")
        db = datastore.open("bfile.txt", "r")
        dbfiles = [x for x in db.readlines()]
        db1 = datastore.open("cfile.txt", "r")
        dbfiles1 = [x for x in db1.readlines()]
        try:
            for b in dbfiles:
                for d in dbfiles1:
                    bdir = b.replace("[name]", d.strip())
                    url = urljoin(start_url, bdir)
                    output.debug("Testing: %s" % url)
                    resp = request.send(
                        url=url, method="GET", payload=None, headers=None
                    )
                    if resp.status_code == 200:
                        if resp.url == url.replace(" ", "%20"):
                            output.finding(
                                'Found file "%s" Backup at %s' % (d.strip(), resp.url)
                            )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
