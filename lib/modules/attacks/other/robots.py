import re
from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Robots(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        request = Services.get('request_factory')

        output.info('Checking robots paths..')
        try:
            url = urljoin(request.url, 'robots.txt')
            resp = request.send(
                url=url,
                method="GET",
                payload=None,
                headers=None
            )
            if resp.url == url:
                paths = re.findall(r'\ (/\S*)', resp.content)
                if len(paths):
                    for path in paths:
                        if path.startswith('/'):
                            path = path[1:]
                        url2 = urljoin(request.url, path)
                        resp = request.send(
                            url=url2,
                            method="GET",
                            payload=None,
                            headers=None
                        )
                        output.finding(" - [%s] %s" % (resp.status_code, url2))
        except Exception as e:
            print(e)
