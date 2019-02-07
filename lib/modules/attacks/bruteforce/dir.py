import re
from urllib.parse import urljoin

from lib.utils.container import Services
from .. import AttackPlugin


class Dir(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')
        datastore = Services.get('datastore')
        request = Services.get('request_factory')

        output.info('Checking common dirs..')
        with datastore.open('cdir.txt', 'r') as db:
            dbfiles = [x.strip() for x in db]
            try:
                for d in dbfiles:
                    url = urljoin(start_url, d)
                    resp = request.send(
                        url=url,
                        method="GET",
                        payload=None,
                        headers=None
                    )
                    if resp.status_code == 200:
                        if resp.url == url.replace(' ', '%20'):
                            output.finding('Found "%s" directory at %s' % (d, resp.url))
                            if re.search(
                                    r'Index Of|<a href="?C=N;O=D">Name</a>|<A HREF="?M=A">Last modified</A>|Parent Directory</a>|<TITLE>Folder Listing.|<<table summary="Directory Listing"',
                                    str(resp.content), re.I):
                                output.finding('Indexing enabled at %s' % (resp.url))
            except Exception as e:
                print(e)
