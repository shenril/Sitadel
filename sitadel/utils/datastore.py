from __future__ import annotations

import os
from typing import IO

# Directory that contains the "sitadel" package. datastore.py lives at
# sitadel/utils/datastore.py, so three levels up is the directory holding the
# package (the repo root when running from source, or site-packages when
# installed).
_BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


class Datastore:
    """
    Utility to access the common folder for plugins data
    """

    def __init__(self, rootpath: str):
        # Anchor a relative datastore path to the package location so the
        # bundled wordlists are found regardless of the current working
        # directory (e.g. after a system-wide install). See issue #48.
        if os.path.isabs(rootpath):
            self.rootpath = rootpath
        else:
            self.rootpath = os.path.join(_BASE_DIR, rootpath)

    def open(self, filename: str, mode: str) -> IO:
        return open(os.path.join(self.rootpath, filename), mode, encoding="utf-8")
