import socket
import subprocess
from urllib.parse import urlparse

from lib.utils.container import Services
from .. import AttackPlugin


class Crime(AttackPlugin):
    def process(self, start_url, crawled_urls):
        output = Services.get('output')

        output.info('Scanning crime (SPDY) vuln...')
        ip = ''
        port = '443'
        try:
            ip += socket.gethostbyname(urlparse(start_url).hostname)
            socket.inet_aton(ip)
            r = subprocess.Popen(
                ['timeout', '4', 'openssl', 's_client', '-connect', ip + ":" + str(port), "-nextprotoneg", "NULL"],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE).communicate()[0]
            if 'Protocols advertised by server' not in r:
                output.finding('That site is vulnerable to CRIME (SPDY), CVE-2012-4929.')
        except Exception as e:
            print(e)
