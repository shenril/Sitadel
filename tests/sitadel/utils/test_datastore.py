import os

from sitadel.utils.datastore import Datastore


def test_relative_rootpath_resolves_to_package(tmp_path, monkeypatch):
    # Run from an unrelated directory; the bundled wordlist must still open.
    monkeypatch.chdir(str(tmp_path))
    ds = Datastore("sitadel/data")
    with ds.open("admin.txt", "r") as fh:
        if not fh.readline():
            raise AssertionError("bundled data file should be readable")


def test_absolute_rootpath_is_preserved(tmp_path):
    abs_path = str(tmp_path)
    ds = Datastore(abs_path)
    if ds.rootpath != abs_path:
        raise AssertionError

    # A file placed under the absolute rootpath is opened from there.
    with open(os.path.join(abs_path, "sample.txt"), "w", encoding="utf-8") as fh:
        fh.write("payload\n")
    with ds.open("sample.txt", "r") as fh:
        if fh.read().strip() != "payload":
            raise AssertionError
