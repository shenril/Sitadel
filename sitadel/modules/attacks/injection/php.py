import re
from sitadel.utils.container import Services
from .. import AttackPlugin


class Php(AttackPlugin):
    # PHP code injection only makes sense against a PHP application.
    requires = {"lang": "php"}
    output = Services.get("output")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        if resp.status_code == 200 and re.search(
            r'<title>phpinfo[()]</title>|<h1 class="p">PHP Version (.*?)</h1>',
            resp.text,
        ):
            return "PHP Code Injection"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking php code injection...")
        payload = "1;phpinfo()"
        self.run_injection([payload], crawled_urls, self.detect)
