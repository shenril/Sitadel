import re

from lib.utils.container import Services
from .. import AttackPlugin


class HtmlObject(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        request = Services.get('request_factory')

        output.info('Checking html object..')
        try:
            resp = request.send(
                url=start_url,
                method="GET",
                payload=None,
                headers=None
            )
            if re.search(r'<object.*?>.*?<\/object>', resp.content, re.I):
                output.finding('Found HTML Object, logs the existence of HTML object tags at:' % request.url)
        except Exception as e:
            print(e)
