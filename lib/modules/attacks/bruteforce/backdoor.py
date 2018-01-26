from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Backdoor(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        datastore = Services.get('datastore')
        request = Services.get('request_factory')

        output.info('Checking common backdoors...')
        with datastore.open('backdoor.txt', 'r') as db:
            dbfiles = [x.strip() for x in db.readlines()]
            try:
                for payload in dbfiles:
                    url = urljoin(start_url, payload[0])
                    resp = request.send(
                        url=url,
                        method="HEAD",
                        payload=None,
                        headers=None
                    )
                    if resp.status_code == 200:
                        if resp.url == url.replace(' ', '%20'):
                            output.finding('Found Backdoor at %s' % resp.url)
            except Exception as e:
                print(e)
