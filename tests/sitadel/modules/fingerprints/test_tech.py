import json
import os

from sitadel.modules.fingerprints.tech.wappalyzer import match_signatures

_SIGS = {
    "nginx": {"category": "server", "headers": {"Server": "nginx"}},
    "PHP": {"category": "lang", "headers": {"X-Powered-By": "PHP"}},
    "WordPress": {"category": "cms", "html": "wp-content"},
}


def test_matches_headers_and_html():
    detected = match_signatures(
        _SIGS,
        {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"},
        "<link href='/wp-content/themes/x.css'>",
    )
    if detected.get("nginx") != "server":
        raise AssertionError
    if detected.get("PHP") != "lang":
        raise AssertionError
    if detected.get("WordPress") != "cms":
        raise AssertionError


def test_no_false_positive():
    detected = match_signatures(_SIGS, {"Server": "Apache"}, "nothing here")
    if "nginx" in detected or "WordPress" in detected:
        raise AssertionError


def test_bundled_dataset_is_valid():
    path = os.path.join("sitadel", "data", "fingerprints.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not data:
        raise AssertionError
    for tech, sig in data.items():
        if "category" not in sig:
            raise AssertionError(f"{tech} missing category")
