import sitadel


def test_console_entrypoint_exists():
    # pyproject.toml exposes `sitadel = "sitadel:main"` as a console script.
    if not callable(sitadel.main):
        raise AssertionError
