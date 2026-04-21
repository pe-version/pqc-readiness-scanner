from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }[self.value]


@dataclass(frozen=True)
class Finding:
    algorithm_id: str
    algorithm_display: str
    severity: Severity
    category: str
    location: str
    line: int | None
    context: str
    scanner: str
    replacement: str
    notes: str

    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.location, self.line or 0)
