"""Semantic fixture checks are independent of model outputs and quality scores."""

from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path

import pytest

from scripts.build_realistic_fixture import build_fixture, validate_fixture, write_fixture


def test_fixture_is_reproducible_and_outage_only_removes_declared_network_rows(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    manifest = write_fixture(first)
    assert write_fixture(second) == manifest
    complete = [json.loads(line) for line in (first / "events.jsonl").read_text().splitlines()]
    partial = [json.loads(line) for line in (first / "network-outage.jsonl").read_text().splitlines()]
    assert manifest["outage_excluded_count"] > 0
    retained = {r["event"]["event_id"] for r in partial}
    for row in complete:
        should_omit = (row["host"] == "ws-17.corp.example" and row["index"] == "th_real_v1_network"
                       and "2026-01-06T12:00:00Z" <= row["event"]["event_time_utc"] < "2026-01-06T18:00:00Z")
        assert (row["event"]["event_id"] not in retained) == should_omit
    for name, digest in manifest["content_hashes"].items():
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == digest
        assert (first / name).read_bytes() == (second / name).read_bytes()
    with pytest.raises(FileExistsError):
        write_fixture(first)


def test_image_load_can_hash_a_different_file_from_its_hosting_process():
    rows, _ = build_fixture()
    loaded = next(r["event"] for r in rows if r["event"]["action"] == "image_load")
    assert loaded["process"] != loaded["file_name"]
    validate_fixture(rows)


@pytest.mark.parametrize("defect, expected", [
    ("metadata_host", "unknown host"),
    ("metadata_time", "event time"),
    ("raw_metadata", "undeclared/answer field"),
    ("answer_label", "undeclared/answer field"),
    ("process_image", "file name disagree"),
    ("source_ip", "stable address"),
    ("process_lifetime", "process lifetime"),
    ("session", "authenticated session"),
    ("hash", "SHA-256"),
    ("duplicate", "duplicate event"),
])
def test_impossible_or_undeclared_fixture_states_are_rejected(defect, expected):
    rows, _ = build_fixture()
    process = next(r for r in rows if r["event"]["action"] == "process_start")
    connection = next(r for r in rows if r["event"]["action"] == "connection")
    if defect == "metadata_host":
        process["host"] = "127.0.0.1"
    elif defect == "metadata_time":
        process["time"] += 3600
    elif defect == "raw_metadata":
        process["event"]["index"] = process["index"]
    elif defect == "answer_label":
        process["event"]["expected_malicious"] = True
    elif defect == "process_image":
        process["event"]["file_name"] = "different.exe"
    elif defect == "source_ip":
        connection["event"]["src_ip"] = "10.40.8.99"
    elif defect == "process_lifetime":
        connection["event"]["process_guid"] = "not-a-collected-process"
    elif defect == "session":
        connection["event"]["session_id"] = "not-an-observed-session"
    elif defect == "hash":
        process["event"]["file_hash"] = "123"
    elif defect == "duplicate":
        rows.append(deepcopy(process))
    with pytest.raises(ValueError, match=expected):
        validate_fixture(rows)


def test_connection_after_process_exit_is_rejected():
    rows, _ = build_fixture()
    connection = next(r for r in rows if r["event"]["action"] == "connection")
    end = next(r for r in rows if r["event"].get("process_guid") == connection["event"]["process_guid"]
               and r["event"]["action"] == "process_end")
    at = datetime.fromisoformat(end["event"]["event_time_utc"]) + timedelta(seconds=1)
    connection["time"] = at.timestamp()
    connection["event"]["event_time_utc"] = at.isoformat()
    connection["event"]["collected_time_utc"] = at.isoformat()
    with pytest.raises(ValueError, match="process lifetime"):
        validate_fixture(rows)


def test_frozen_files_match_the_generator_and_private_expectations(tmp_path):
    frozen = Path(__file__).parent / "fixtures" / "normalized-v1"
    generated = tmp_path / "generated"
    write_fixture(generated)
    for name in ("events.jsonl", "network-outage.jsonl", "manifest.json", "expectations.json"):
        assert (frozen / name).read_bytes() == (generated / name).read_bytes()
