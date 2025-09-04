# audit-log-platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An immutable audit platform: SHA-256 hash-chained records, pluggable sinks (memory / JSONL file), actor-action queries, and tamper detection that pinpoints the exact broken sequence.

## 🚀 Overview

Audit logs only matter if they *prove* they haven't been edited. `audit-log-platform` chains every record to its predecessor: each entry's hash covers its content plus the previous record's hash, so any mutation — even a single field — breaks verification at a precisely identified sequence. Records flow through pluggable sinks; the JSONL sink survives process restarts and reloads the chain intact.

## ✨ Features

- **Hash chain:** GENESIS-rooted, SHA-256, canonical JSON serialization per record
- **Tamper pinpointing:** `verify_chain()` returns the first broken sequence; `verify_or_raise()` throws `TamperDetectedError`
- **Pluggable sinks:** `InMemorySink` (tests) · `JsonlFileSink` (durable, append-only file)
- **Structured queries:** filter by actor/action, newest-first with limit
- **Injectable clock:** deterministic timestamps for tests
- **Frozen records** — immutability enforced at the data level
- **Zero dependencies**

## 🚧 Structure

```
audit-log-platform/
├── src/audit_platform/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/audit-log-platform.git
cd audit-log-platform
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from pathlib import Path
from audit_platform import AuditPlatform, JsonlFileSink

platform = AuditPlatform(sink=JsonlFileSink(Path("logs/audit.jsonl")))
platform.log("alice", "read", "document:42", "allow")
platform.log("bob", "export", "report:7", "deny")

ok, broken_at = platform.verify_chain()
print("intact" if ok else f"tampered at {broken_at}")

for record in platform.query(actor="alice", limit=10):
    print(record.action, record.decision)
```

## 🔧 Error Handling

```text
AuditPlatformError
└── TamperDetectedError   # .sequence identifies the first corrupted record
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen records
- Zero comments — names carry the meaning
- Tampering tests mutate frozen records via object.__setattr__ to prove detection works

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi** - [kooroushmasoumi@gmail.com](mailto:kooroushmasoumi@gmail.com)

---

⭐ Star this repo if you find it useful!
