import os


class Datastore:
    """
    Utility to access the common folder for plugins data
    """

    def __init__(self, rootpath):
        self.rootpath = rootpath

    def open(self, filename, mode):
        return open(os.path.join(self.rootpath, filename), mode,encoding="utf-8")
