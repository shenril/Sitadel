import pytest
import requests

from lib.request.request import SingleRequest


def test_request():
    r = SingleRequest()
    assert hasattr(r, 'send')

    r1 = SingleRequest(url='test', agent='agent', proxy='proxy', redirect='redirect', timeout='timeout')
    assert r1.url == 'test'
    assert r1.agent == 'agent'
    assert r1.proxy == 'proxy'
    assert r1.redirect == 'redirect'
    assert r1.timeout == 'timeout'
    assert isinstance(r1.ruagent, str)


def test_request_send():
    req = SingleRequest()
    with pytest.raises(requests.exceptions.MissingSchema):
        req.send(url='test')

    assert req.send(url='http://example.com').request.method == 'GET'
    assert req.send(url='http://example.com', method='post').request.method == 'POST'
