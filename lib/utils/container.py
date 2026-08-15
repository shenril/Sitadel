from __future__ import annotations

from typing import Any


class Services:
    services: dict[str, Any] = {}

    @classmethod
    def get(cls, key: str) -> Any:
        try:
            if cls.services[key] is None:
                raise NameError("No service registered with this name")
            return cls.services[key]
        except KeyError:
            raise NameError("No service registered with this name")

    @classmethod
    def register(cls, name: str, instance: Any) -> None:
        cls.services[name] = instance
