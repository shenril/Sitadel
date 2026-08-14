class IPlugin(type):
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'plugins'):
            # this is the base class.  Create an empty registry
            cls.plugins = []
        else:
            # this is a derived class.  Register it unconditionally; the
            # risk level is applied at run time (see ``*Plugin.enabled``),
            # not here at import time, so registration no longer depends on
            # ``settings.risk`` being loaded before the module is imported.
            cls.plugins.append(cls)

        super(IPlugin, cls).__init__(name, bases, dct)
