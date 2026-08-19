from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TargetProfile:
    """Structured picture of the target built by the fingerprint phase.

    Technologies are grouped by category (``server``, ``lang``, ``framework``,
    ``cms``, ``frontend``, ``cdn``, ``waf``, ``system`` … — the same names as
    the fingerprint plugin packages). The attack phase consults this profile to
    decide which attack classes are worth launching (see ``AttackPlugin``).
    """

    technologies: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    # Detected API style, e.g. "rest" or "graphql". Set by the API-discovery
    # step (or fingerprinting) and consulted to gate API-only attacks.
    api_type: str | None = None

    def add(self, category: str, name) -> None:
        if category and name:
            self.technologies[str(category).lower()].add(str(name))

    def is_api(self) -> bool:
        """Whether the target looks like an API worth body-injection testing."""
        return self.api_type in ("rest", "graphql")

    def get(self, category: str) -> str | None:
        """Return the detections for a category as a string, or None."""
        values = self.technologies.get(str(category).lower())
        return ", ".join(sorted(values)) if values else None

    def has(self, category: str) -> bool:
        return bool(self.technologies.get(str(category).lower()))

    def as_dict(self) -> dict:
        return {cat: sorted(names) for cat, names in self.technologies.items()}

    def summary(self) -> str:
        return "; ".join(
            f"{cat}={self.get(cat)}" for cat in sorted(self.technologies)
        )
