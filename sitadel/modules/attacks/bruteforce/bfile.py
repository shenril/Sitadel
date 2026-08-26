from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from sitadel.utils.container import Services
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
        with self.datastore.open("bfile.txt", "r") as db:
            dbfiles = [x.strip() for x in db]
        with self.datastore.open("cfile.txt", "r") as db1:
            dbfiles1 = [x.strip() for x in db1]
        urls = []
        for b in dbfiles:
            for d in dbfiles1:
                bdir = b.replace("[name]", d)
                urls.append(urljoin(str(start_url), str(bdir)))
        # Bounded thread pool so the wordlist is probed concurrently.
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.check_url, url) for url in urls]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
