import os.path
from enum import IntEnum

import yaml


class Risk(IntEnum):
    """
    Enumeration of the risk for the plugins
    0 NO_DANGER Almost no risk to be detected
    1 NOISY Generates lot of requests and patterns that may be detected
    2 DANGEROUS Perform exploitation stage and may be potentially harmful to the target
    """
    NO_DANGER = 0
    NOISY = 1
    DANGEROUS = 2


class Settings(object):
    cfg = {}

    _setters = ['risk', 'dns_resolver', 'datastore']

    def __getattr__(self, item):
        return Settings.cfg[item]

    def __setattr__(self, key, value):
        if key in Settings._setters:
            Settings.cfg[key] = value
        else:
            raise NameError("You cannot redefine the value of %s dynamically\nPlease use the config file" % key)

    @classmethod
    def from_yaml(cls, filepath):
        """
        Generate the configuration dictionary from yaml file
        :param filepath: config file path
        :return: None
        """
        # Check if the filepath provided exists
        if not os.path.isfile(filepath):
            raise FileNotFoundError("Invalid path for the configuration file")

        # Parse the configuration and merge it in dict
        with open(filepath, 'r') as yamlfile:
            try:
                # Getting config from the file
                config = yaml.load(yamlfile, Loader=yaml.SafeLoader)
                # Merging the dictionaries and getting result
                cls.cfg = {**cls.cfg, **config}
            except yaml.YAMLError as e:
                print(e)
