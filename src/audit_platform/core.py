from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


class AuditPlatformError(Exception):
    pass


class TamperDetectedError(AuditPlatformError):
    def __init__(self, sequence: int) -> None:
        super().__init__(f"tampering detected at sequence {sequence}")
        self.sequence = sequence


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    actor: str
    action: str
    resource: str
    decision: str
    occurred_at: float
    prev_hash: str
    record_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "decision": self.decision,
            "occurred_at": self.occurred_at,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


GENESIS = "0" * 64


def compute_hash(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_record(sequence: int, actor: str, action: str, resource: str,
                 decision: str, occurred_at: float, prev_hash: str) -> AuditRecord:
    body = {
        "sequence": sequence,
        "actor": actor,
        "action": action,
        "resource": resource,
