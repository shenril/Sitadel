from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from lib.utils.container import Services
from .. import AttackPlugin


class Bfile(AttackPlugin):
    output = Services.get("output")
    datastore = Services.get("datastore")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def check_url(self, url):
        try:
            self.output.debug("Testing: %s" % url)
            resp = self.request.send(url=url, method="HEAD", payload=None, headers=None)
            if resp.status_code == 200:
                self.output.finding("Found backup file at %s" % (resp.url))
        except Exception as e:
            self.logger.error(e)
            self.output.error("Error occured\nAborting this attack...\n")
            self.output.debug("Traceback: %s" % e)
            return

    def process(self, start_url, crawled_urls):
        self.output.info("Checking common backup files..")
        db = self.datastore.open("bfile.txt", "r")
        dbfiles = [x for x in db.readlines()]
        db1 = self.datastore.open("cfile.txt", "r")
        dbfiles1 = [x for x in db1.readlines()]
        urls = []
        for b in dbfiles:
            for d in dbfiles1:
                bdir = b.replace("[name]", d.strip())
                urls.append(urljoin(str(start_url), str(bdir)))
        # We launch ThreadPoolExecutor with max_workers to None to get default optimization
        # https://docs.python.org/3/library/concurrent.futures.html
        with PoolExecutor(max_workers=None) as executor:
            try:
                for _ in executor.map(self.check_url, urls):
                    pass
            except KeyboardInterrupt:
                executor.shutdown()

