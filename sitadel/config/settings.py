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
    # Safe default risk so plugin filtering works even before a config is
    # loaded (matches the default shipped in config/config.yml).
    cfg = {'risk': Risk.NOISY}

    _setters = ['risk', 'dns_resolver', 'datastore']

    def __getattr__(self, item):
        try:
            return Settings.cfg[item]
        except KeyError:
            raise AttributeError(item)

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
                # Normalize the risk to the Risk enum so comparisons against
                # plugin levels are consistent regardless of the source (an
                # int from YAML or a Risk from the CLI).
                if 'risk' in cls.cfg:
                    cls.cfg['risk'] = Risk(int(cls.cfg['risk']))
            except yaml.YAMLError as e:
                print(e)
