import re
from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Phpinfo(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        datastore = Services.get("datastore")
        logger = Services.get("logger")

        output.info("Checking phpinfo..")
        db = datastore.open("phpinfo.txt", "r")
        dbfiles = [x.split("\n") for x in db]
        try:
            for d in dbfiles:
                url = urljoin(start_url, str(d[0]))
                resp = request.send(url=url, method="GET", payload=None, headers=None)
                if re.search(
                    r'<h1 class="p">PHP Version (.*?)</h1>|(<tr class="h"><td>\n|alt="PHP Logo" /></a>)',
                    resp.text,
                ):
                    output.finding("Found phpinfo page at %s" % (resp.url))
                    break
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return
