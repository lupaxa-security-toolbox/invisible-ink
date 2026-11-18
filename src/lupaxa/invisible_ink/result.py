"""Stable JSON result envelopes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Result:
    """One command result."""

    command: str
    success: bool = True
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def add_error(self, code: str, message: str, *, exit_code: int) -> None:
        """Record a failure and mark the result unsuccessful."""
        self.success = False
        self.errors.append({"code": code, "message": message, "exit_code": exit_code})

    def to_json(self) -> str:
        """Serialise the envelope without colour codes."""
        payload = {
            "schema_version": 1,
            "command": self.command,
            "success": self.success,
            "data": self.data,
            "warnings": self.warnings,
            "errors": self.errors,
        }
        return json.dumps(payload, indent=2, sort_keys=True)
