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

    @classmethod
    def make_multiple_requests(cls, **kwargs):
        return MultipleHTTPRequests(**kwargs)

    @classmethod
    def make_single_request(cls, **kwargs):
        return SingleHTTPRequest(**kwargs)

    @classmethod
    def make_dns_request(cls, **kwargs):
        return DNSRequest(**kwargs)
