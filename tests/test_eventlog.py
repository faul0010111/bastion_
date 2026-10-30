import json
import time

import pytest

from bastion.errors import LogIntegrityError
from bastion.eventlog import EventLog, query_records, verify_log


def fill(path, n=5):
    log = EventLog(path)
    for i in range(n):
        log.append("event", {"type": "modified", "path": f"a{i}.txt"})
    return log


def test_chain_verifies_and_continues_after_reopen(tmp_path):
    p = tmp_path / "log.jsonl"
    log = fill(p, 3)
    head = log.head
    assert verify_log(p).ok and verify_log(p).head == head
    reopened = EventLog(p)
    reopened.append("alert", {"rule": "x"})
    result = verify_log(p)
    assert result.ok and result.records == 4


def test_edited_record_is_detected(tmp_path):
    p = tmp_path / "log.jsonl"
    fill(p, 5)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["data"]["path"] = "other.txt"
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    r = verify_log(p)
    assert not r.ok and r.bad_seq == 3 and "altered" in r.error


def test_removed_record_is_detected(tmp_path):
    p = tmp_path / "log.jsonl"
    fill(p, 5)
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert not verify_log(p).ok


def test_garbage_line_is_detected(tmp_path):
    p = tmp_path / "log.jsonl"
    fill(p, 2)
    with open(p, "a") as fh:
        fh.write("this is not json\n")
    assert not verify_log(p).ok


def test_refuses_to_append_to_broken_chain(tmp_path):
    p = tmp_path / "log.jsonl"
    fill(p, 3)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    with pytest.raises(LogIntegrityError):
        EventLog(p)


def test_anchor_detects_truncation(tmp_path):
    p = tmp_path / "log.jsonl"
    log = fill(p, 5)
    anchor = log.head
    assert verify_log(p, anchor=anchor).anchor_found is True
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:3]) + "\n")  # clean cut at the end: the chain stays valid...
    r = verify_log(p, anchor=anchor)
    assert r.ok and r.anchor_found is False   # ...but the noted anchor exposes the truncation


def test_query_filters(tmp_path):
    p = tmp_path / "log.jsonl"
    log = EventLog(p)
    t0 = time.time()
    log.append("event", {"type": "created", "path": "docs/a.txt"}, ts=t0 - 100)
    log.append("event", {"type": "deleted", "path": "docs/b.txt"}, ts=t0 - 50)
    log.append("alert", {"rule": "mass_deletion", "path": ""}, ts=t0 - 10)
    assert len(query_records(p)) == 3
    assert [r["data"]["path"] for r in query_records(p, kind="event", event_type="deleted")] == ["docs/b.txt"]
    assert len(query_records(p, rule="mass_deletion")) == 1
    assert len(query_records(p, since=t0 - 60)) == 2
    assert len(query_records(p, path_contains="A.TXT")) == 1
    assert len(query_records(p, limit=2)) == 2


def test_missing_log_is_empty_and_valid(tmp_path):
    assert verify_log(tmp_path / "nothing.jsonl").ok
    assert query_records(tmp_path / "nothing.jsonl") == []
