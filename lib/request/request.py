import sys

from requests import Request, Session
from requests import RequestException
import urllib3

from . import ragent as ragent
from lib.utils.container import Services

# Create a RequestFactory with getSingleRequest, getParallelRequests+enqueue
class SingleRequest:
    def __init__(self, **kwargs):
        self.url = None if "url" not in kwargs else kwargs["url"]
        self.agent = "Sitadel" if "agent" not in kwargs else kwargs["agent"]
        self.proxy = None if "proxy" not in kwargs else kwargs["proxy"]
        self.redirect = True if "redirect" not in kwargs else kwargs["redirect"]
        self.timeout = None if "timeout" not in kwargs else kwargs["timeout"]
        self.ruagent = ragent.RandomUserAgent()

    def send(self, url, method="GET", payload=None, headers=None, cookies=None):
        # requests session
        output = Services.get('output')
        request = Session()
        prepped=self.prepare_request(url,method,payload,headers,cookies)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            resp=request.send(
                prepped,
                timeout=self.timeout,
                proxies={
                    'http': self.proxy,
                    'https': self.proxy,
                    'ftp': self.proxy,
                },
                allow_redirects=self.redirect,
                verify=False)
            return resp
        except TimeoutError:
            output.error("Timeout error on the URL: %s" % url)
        except RequestException as err:
            output.error("Error while trying to contact the website: \n {0}\n".format(err))
            raise(err)

    def prepare_request(self, url, method, payload, headers, cookies):
        if payload is None:
            payload = {}
        if headers is None:
            headers = {}
        if cookies is not None:
            cookies = {cookies: ''}
        if "--random-agent" in sys.argv:
            headers['User-Agent'] = self.ruagent
        else:
            headers['User-Agent'] = self.agent
        # get method
        if method.upper() == "GET":
            req = Request(
                method=method.upper(),
                url=url,
                headers=headers,
                cookies=cookies,
            ).prepare()
        # post method
        elif method.upper() == "POST":
            req = Request(
                method=method.upper(),
                url=url,
                data=payload,
                headers=headers,
                cookies=cookies,
            ).prepare()
        # other methods
        else:
            req = Request(
                method=method.upper(),
                url=url,
                data=payload,
                headers=headers,
                cookies=cookies,
            ).prepare()
        # return all "req" attrs
        return req
