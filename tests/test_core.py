import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from audit_platform import (
    AuditPlatform,
    AuditPlatformError,
    InMemorySink,
    JsonlFileSink,
    TamperDetectedError,
)


@pytest.fixture
def platform():
    return AuditPlatform()


def test_log_appends_sequential_records(platform):
    for i in range(3):
        platform.log("admin", f"action-{i}", "resource", "allow")
    records = platform.query()
    assert [r.sequence for r in reversed(records)] == [1, 2, 3]
    assert platform.size == 3


def test_empty_actor_rejected(platform):
    with pytest.raises(AuditPlatformError):
        platform.log("", "read", "doc", "allow")


def test_chain_verifies_when_untouched(platform):
    for i in range(5):
        platform.log("user", "read", f"doc-{i}", "allow")
    ok, broken_at = platform.verify_chain()
    assert ok
    assert broken_at is None


def test_verify_or_raise_silent_when_clean(platform):
    platform.log("u", "a", "r", "allow")
    platform.verify_or_raise()


def test_record_mutation_breaks_chain(platform):
    platform.log("user", "read", "doc", "allow")
    platform.log("user", "write", "doc", "deny")
    tampered = platform._sink.all_records()[0]
    object.__setattr__(tampered, "decision", "mutated")
    ok, broken_at = platform.verify_chain()
    assert not ok
    assert broken_at == 1


def test_verify_or_raise_raises_on_tampering(platform):
    platform.log("user", "read", "doc", "allow")
    record = platform._sink.all_records()[0]
    object.__setattr__(record, "actor", "someone-else")
    with pytest.raises(TamperDetectedError) as excinfo:
        platform.verify_or_raise()
    assert excinfo.value.sequence == 1


def test_query_filters_by_actor_and_action(platform):
    platform.log("alice", "read", "d1", "allow")
    platform.log("bob", "write", "d2", "deny")
    alice_only = platform.query(actor="alice")
    write_only = platform.query(action="write")
    assert all(r.actor == "alice" for r in alice_only)
