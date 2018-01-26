class MultipleHTTPRequests:

    def __init__(self, url):
        self.url = url


class SingleHTTPRequest:
    pass


class DNSRequest:
    pass


class RequestFactory:
    def __init__(self):
        pass

    def make_multiple_requests(self, **kwargs):
        return MultipleHTTPRequests(**kwargs)

    def make_single_request(self, **kwargs):
        return SingleHTTPRequest(**kwargs)

    def make_dns_request(self, **kwargs):
        return DNSRequest(**kwargs)
