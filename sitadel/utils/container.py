from __future__ import annotations

from typing import Any


class ServiceNotFound(NameError):
    """Raised when a service is requested but not registered.

    Subclasses ``NameError`` so existing ``except NameError`` guards (used
    throughout as an "is this service registered?" check) keep working, while
    tracebacks and targeted ``except ServiceNotFound`` reads clearly.
    """


class Services:
    services: dict[str, Any] = {}

    @classmethod
    def get(cls, key: str) -> Any:
        service = cls.services.get(key)
        if service is None:
            raise ServiceNotFound(f"No service registered under {key!r}")
        return service

    @classmethod
    def register(cls, name: str, instance: Any) -> None:
        cls.services[name] = instance
