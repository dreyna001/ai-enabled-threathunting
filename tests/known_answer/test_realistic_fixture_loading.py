from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from scripts.build_realistic_fixture import build_fixture
from scripts.load_realistic_fixture import local_origin, run, verify_rows


FIXTURE = Path(__file__).parent / "fixtures" / "normalized-v1" / "events.jsonl"


def indexed(rows):
    import json
    return [{"_raw": json.dumps(r["event"]), "_time": datetime.fromtimestamp(r["time"], timezone.utc).isoformat(),
             **{k: r[k] for k in ("host", "index", "sourcetype")}} for r in rows]


def test_indexed_envelope_matches_exactly_and_rejects_duplicate_metadata():
    expected, _ = build_fixture()
    observed = indexed(expected)
    verify_rows(expected, observed)
    observed[0]["host"] = [expected[0]["host"], "127.0.0.1"]
    with pytest.raises(ValueError, match="metadata"):
        verify_rows(expected, observed)


def test_duplicate_events_and_wrong_indexed_times_are_rejected():
    expected, _ = build_fixture()
    observed = indexed(expected)
    with pytest.raises(ValueError, match="duplicate"):
        verify_rows(expected, observed + observed[:1])
    observed[0]["_time"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="event time"):
        verify_rows(expected, observed)


@pytest.mark.parametrize("origin", ["https://example.com", "http://10.0.0.1", "https://user:pass@127.0.0.1", "https://127.0.0.1/path"])
def test_loader_cannot_target_a_remote_or_credential_bearing_origin(origin):
    with pytest.raises(ValueError):
        local_origin(origin)


def test_uncertain_hec_request_is_not_reposted(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.load_realistic_fixture.observed_rows", lambda client: [])
    monkeypatch.setattr("scripts.load_realistic_fixture.target_index_counts", lambda client: {"index": 0})
    calls = []

    def timeout(request):
        calls.append(request)
        raise httpx.ReadTimeout("unknown ingestion outcome")

    with httpx.Client(base_url="https://127.0.0.1", transport=httpx.MockTransport(timeout)) as client:
        with pytest.raises(httpx.ReadTimeout):
            run("load", fixture=FIXTURE, output=tmp_path, search=client, hec=client)
        with pytest.raises(FileExistsError):
            run("load", fixture=FIXTURE, output=tmp_path, search=client, hec=client)
    assert len(calls) == 1
    assert (tmp_path / "ingestion-attempt.json").exists()


def test_nonempty_indexes_prevent_ingestion(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.load_realistic_fixture.observed_rows", lambda client: [{"existing": True}])
    with httpx.Client() as client:
        with pytest.raises(ValueError, match="nonempty"):
            run("load", fixture=FIXTURE, output=tmp_path, search=client, hec=client)
    assert not (tmp_path / "ingestion-attempt.json").exists()


def test_role_filtered_empty_search_cannot_cause_a_duplicate_load(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.load_realistic_fixture.observed_rows", lambda client: [])
    monkeypatch.setattr("scripts.load_realistic_fixture.target_index_counts", lambda client: {"index": 689})
    with httpx.Client() as client:
        with pytest.raises(ValueError, match="nonempty"):
            run("load", fixture=FIXTURE, output=tmp_path, search=client, hec=client)
    assert not (tmp_path / "ingestion-attempt.json").exists()
