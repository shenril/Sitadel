from lib.request.ragent import RandomUserAgent


def test_random_agent():
    if not isinstance(RandomUserAgent(), str):
        raise AssertionError
    ra = RandomUserAgent()
    if "Mozilla" not in ra and "Opera" not in ra:
        raise AssertionError
