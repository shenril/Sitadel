from lib.model import TargetProfile


def test_add_get_has_summary():
    profile = TargetProfile()
    profile.add("lang", "PHP")
    profile.add("Lang", "PHP")          # case-insensitive, de-duplicated
    profile.add("server", "nginx")
    profile.add("empty", None)          # ignored

    if profile.get("lang") != "PHP":
        raise AssertionError
    if not profile.has("server"):
        raise AssertionError
    if profile.get("cms") is not None:
        raise AssertionError
    if profile.has("empty"):
        raise AssertionError
    if "lang=PHP" not in profile.summary():
        raise AssertionError
