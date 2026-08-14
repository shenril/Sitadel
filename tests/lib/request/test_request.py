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


def test_random_agent():
    # Default: the configured agent is used.
    fixed = SingleRequest(agent="fixed-agent")
    prepped = fixed.prepare_request("http://example.com", "GET", None, None, None)
    if prepped.headers["User-Agent"] != "fixed-agent":
        raise AssertionError

    # With random_agent enabled, a random agent is used instead.
    rnd = SingleRequest(agent="fixed-agent", random_agent=True)
    prepped = rnd.prepare_request("http://example.com", "GET", None, None, None)
    if prepped.headers["User-Agent"] == "fixed-agent":
        raise AssertionError


def test_request_send_returns_none_on_error():
    # A connection error (nothing listening on this local port) must be
    # handled and return None rather than raising and aborting the scan.
    Services.register("output", Output())
    req = SingleRequest(timeout=2)
    if req.send(url="http://127.0.0.1:1/") is not None:
        raise AssertionError
