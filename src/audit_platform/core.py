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
        "decision": decision,
        "occurred_at": occurred_at,
        "prev_hash": prev_hash,
    }
    return AuditRecord(
        sequence=sequence, actor=actor, action=action,
        resource=resource, decision=decision, occurred_at=occurred_at,
        prev_hash=prev_hash, record_hash=compute_hash(body),
    )


class Sink(Protocol := object):
    pass


class InMemorySink:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    def all_records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def last_sequence(self) -> int:
        with self._lock:
            return self._records[-1].sequence if self._records else 0

    def find_by_actor(self, actor: str) -> list[AuditRecord]:
        with self._lock:
            return [r for r in self._records if r.actor == actor]

    def tail(self, count: int = 20) -> list[AuditRecord]:
        with self._lock:
            return list(reversed(self._records[-count:]))


class JsonlFileSink(InMemorySink):
    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    data = json.loads(line)
                    self._records.append(AuditRecord(**data))

    def append(self, record: AuditRecord) -> None:
        super().append(record)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.as_dict(), ensure_ascii=False) + "\n")


class AuditPlatform:
    def __init__(self, sink=None, clock: Callable[[], float] | None = None) -> None:
        self._sink = sink or InMemorySink()
        self._clock = clock or time.time
        self.total_appended = 0

    def log(self, actor: str, action: str, resource: str, decision: str) -> AuditRecord:
        if not actor.strip() or not action.strip():
            raise AuditPlatformError("actor and action are required")
        previous = self.last_hash()
        record = build_record(
            sequence=self._sink.last_sequence() + 1,
            actor=actor, action=action, resource=resource, decision=decision,
            occurred_at=self._clock(), prev_hash=previous,
        )
        self._sink.append(record)
        self.total_appended += 1
        return record

    def verify_chain(self) -> tuple[bool, int | None]:
        expected_prev = GENESIS
        for index, record in enumerate(self._sink.all_records()):
            if record.prev_hash != expected_prev:
                return False, record.sequence
            body = {
                "sequence": record.sequence,
                "actor": record.actor,
                "action": record.action,
                "resource": record.resource,
                "decision": record.decision,
                "occurred_at": record.occurred_at,
                "prev_hash": record.prev_hash,
            }
            if compute_hash(body) != record.record_hash:
                return False, record.sequence
            expected_prev = record.record_hash
        return True, None

    def verify_or_raise(self) -> None:
        ok, broken_at = self.verify_chain()
        if not ok:
            raise TamperDetectedError(broken_at)

    def last_hash(self) -> str:
        records = self._sink.all_records()
        return records[-1].record_hash if records else GENESIS

    def query(self, actor: str | None = None,
              action: str | None = None, limit: int = 50) -> list[AuditRecord]:
        results = self._sink.all_records()
        if actor is not None:
            results = [r for r in results if r.actor == actor]
        if action is not None:
            results = [r for r in results if r.action == action]
        return list(reversed(results[-limit:]))

    @property
    def size(self) -> int:
        return len(self._sink.all_records())
