from lib.config import settings


class IPlugin(type):
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'plugins'):
            # this is the base class.  Create an empty registry
            cls.plugins = []
        else:
            # this is a derived class.  Add cls to the registry
            if hasattr(cls, 'level') and getattr(cls, 'level') <= settings.risk:
                cls.plugins.append(cls)

        super(IPlugin, cls).__init__(name, bases, dct)
