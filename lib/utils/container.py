class Services(object):
    services = {}

    @classmethod
    def get(cls, key):
        try:
            if cls.services[key] is None:
                raise NameError("No service registered with this name")
            else:
                return cls.services[key]
        except KeyError:
            raise NameError("No service registered with this name")

    @classmethod
    def register(cls, name, instance) -> None:
        cls.services[name] = instance
