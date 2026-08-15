import os

# Directory that contains the "lib" package. datastore.py lives at
# lib/utils/datastore.py, so three levels up is the package root (the repo
# root when running from source, or site-packages when installed).
_BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


class Datastore:
    """
    Utility to access the common folder for plugins data
    """

    def __init__(self, rootpath):
        # Anchor a relative datastore path to the package location so the
        # bundled wordlists are found regardless of the current working
        # directory (e.g. after a system-wide install). See issue #48.
        if os.path.isabs(rootpath):
            self.rootpath = rootpath
        else:
            self.rootpath = os.path.join(_BASE_DIR, rootpath)

    def open(self, filename, mode):
        return open(os.path.join(self.rootpath, filename), mode, encoding="utf-8")
