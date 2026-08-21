import sitadel.cli


def test_console_entrypoint_exists():
    # pyproject.toml exposes `sitadel = "sitadel.cli:main"` as a console script.
    if not callable(sitadel.cli.main):
        raise AssertionError
