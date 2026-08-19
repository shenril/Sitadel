import re
from sitadel.utils.container import Services
from .. import AttackPlugin


class Html(AttackPlugin):
    output = Services.get("output")
    request = Services.get("request_factory")
    logger = Services.get("logger")

    def detect(self, resp, payload):
        # Match the injected HTML literally, not as a regex.
        if resp.status_code == 200 and re.search(re.escape(payload), resp.text):
            return "HTML Code Injection"
        return None

    def process(self, start_url, crawled_urls):
        self.output.info("Checking html injection...")
        payload = '<h1><a href="https://www.github.com/shenril/Sitadel">Click Sitadel!</a></h1>'
        self.run_injection([payload], crawled_urls, self.detect)
