import pytest
import requests

from lib.request.request import SingleRequest
from lib.utils.container import Services
from lib.utils.output import Output


def test_request():
    Services.register("output", Output())

    r = SingleRequest()
    if not hasattr(r, "send"):
        raise AssertionError

    r1 = SingleRequest(
        url="test", agent="agent", proxy="proxy", redirect="redirect", timeout="timeout"
    )
    if r1.url != "test":
        raise AssertionError
    if r1.agent != "agent":
        raise AssertionError
    if r1.proxy != "proxy":
        raise AssertionError
    if r1.redirect != "redirect":
        raise AssertionError
    if r1.timeout != "timeout":
        raise AssertionError
    if not isinstance(r1.ruagent, str):
        raise AssertionError


def test_request_send():
    req = SingleRequest()
    with pytest.raises(requests.exceptions.MissingSchema):
        req.send(url="test")

    if req.send(url="http://example.com").request.method != "GET":
        raise AssertionError
    if req.send(url="http://example.com", method="post").request.method != "POST":
        raise AssertionError
