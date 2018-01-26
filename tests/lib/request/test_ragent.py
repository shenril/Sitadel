from lib.request.ragent import RandomUserAgent


def test_random_agent():
    assert isinstance(RandomUserAgent(), str)
    ra = RandomUserAgent()
    assert "Mozilla" in ra or "Opera" in ra
