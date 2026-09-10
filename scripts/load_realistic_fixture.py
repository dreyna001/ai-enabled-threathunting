#!/usr/bin/env python3
"""Load or verify the frozen normalized v1 fixture in isolated local lab indexes.

Provision the four manifest indexes and a HEC token restricted to them first.
There is no delete, overwrite, automatic ingestion retry, or baseline mutation.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from scripts.build_realistic_fixture import END, SOURCES, START, validate_fixture


def local_origin(value: str) -> str:
    url = urlsplit(value)
    if url.scheme not in {"https", "http"} or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        raise ValueError("a loopback lab origin is required")
    if not url.hostname or not ipaddress.ip_address(url.hostname).is_loopback:
        raise ValueError("fixture loading is restricted to an explicit loopback IP")
    return value.rstrip("/")


def read_fixture(path: Path) -> list[dict[str, Any]]:
    if path.name not in {"events.jsonl", "network-outage.jsonl"}:
        raise ValueError("select a manifest-declared fixture variant")
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("fixture exceeds the bounded lab load size")
    manifest = json.loads((path.parent / "manifest.json").read_text())
    if hashlib.sha256(raw).hexdigest() != manifest["content_hashes"][path.name]:
        raise ValueError("fixture content differs from its frozen manifest")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    validate_fixture(rows)
    return rows


def observed_rows(client: httpx.Client) -> list[dict[str, Any]]:
    indexes = " OR ".join(f'index="{pair[0]}"' for pair in SOURCES.values())
    response = client.post("/services/search/jobs", data={
        "search": f"search ({indexes}) | table _raw _time host index sourcetype",
        "earliest_time": "0", "latest_time": "now", "exec_mode": "blocking", "output_mode": "json",
    })
    response.raise_for_status()
    sid = response.json()["sid"]
    response = client.get(f"/services/search/jobs/{sid}/results", params={"output_mode": "json", "count": "20000"})
    response.raise_for_status()
    return response.json()["results"]


def target_index_counts(client: httpx.Client) -> dict[str, int]:
    response = client.get("/services/data/indexes", params={"output_mode": "json", "count": "0"})
    response.raise_for_status()
    names = {pair[0] for pair in SOURCES.values()}
    counts = {entry["name"]: int(entry["content"]["totalEventCount"])
              for entry in response.json()["entry"] if entry["name"] in names}
    if set(counts) != names:
        raise ValueError("cannot verify all target indexes exist and are empty")
    return counts


def verify_rows(expected: list[dict[str, Any]], observed: list[dict[str, Any]]) -> None:
    by_id = {row["event"]["event_id"]: row for row in expected}
    seen: set[str] = set()
    for row in observed:
        body = json.loads(row["_raw"])
        event_id = body["event_id"]
        if event_id in seen or event_id not in by_id:
            raise ValueError("duplicate or unexpected event in isolated fixture indexes")
        seen.add(event_id)
        original = by_id[event_id]
        if body != original["event"]:
            raise ValueError("indexed raw event differs from the frozen fixture")
        if any(row.get(key) != original[key] for key in ("host", "index", "sourcetype")):
            raise ValueError("indexed source metadata differs or is multivalued")
        when = datetime.fromisoformat(row["_time"])
        if when.tzinfo is None or when.timestamp() != original["time"] or not START <= when < END:
            raise ValueError("indexed event time differs from the HEC envelope")
    if seen != set(by_id):
        raise ValueError("fixture event set is incomplete")


def run(stage: str, *, fixture: Path, output: Path, search: httpx.Client,
        hec: httpx.Client | None = None) -> dict[str, Any]:
    expected = read_fixture(fixture)
    before = observed_rows(search)
    if stage == "load":
        if before or any(target_index_counts(search).values()):
            raise ValueError("target indexes are nonempty; ingestion will not overwrite or append")
        if hec is None:
            raise ValueError("loading requires a HEC client")
        output.mkdir(parents=True, exist_ok=True)
        # Persist intent before a single non-idempotent request. A timeout must
        # be investigated with verify, never treated as permission to repost.
        with (output / "ingestion-attempt.json").open("x") as handle:
            json.dump({"fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                       "event_count": len(expected), "status": "request_pending_or_uncertain"}, handle, indent=2)
        response = hec.post("/services/collector/event", content=fixture.read_bytes(),
                            headers={"Content-Type": "application/json"})
        response.raise_for_status()
        ack_code = response.json().get("code")
        (output / "hec-acknowledgment.json").write_text(json.dumps({"http_status": response.status_code, "code": ack_code}))
        if ack_code != 0:
            raise ValueError("HEC did not acknowledge the fixture request")
        # Only read-only verification is repeated while indexing catches up.
        for _ in range(10):
            before = observed_rows(search)
            if len(before) >= len(expected):
                break
            time.sleep(1)
    elif stage != "verify":
        raise ValueError("unknown fixture stage")
    verify_rows(expected, before)
    output.mkdir(parents=True, exist_ok=True)
    result = {"status": "verified", "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
              "event_count": len(expected), "exact_raw_and_scalar_metadata_match": True,
              "indexes": [pair[0] for pair in SOURCES.values()], "baseline_indexes_modified": False}
    (output / "indexed-rows.json").write_text(json.dumps(before, indent=2))
    (output / "verification.json").write_text(json.dumps(result, indent=2))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("load", "verify"))
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--search-token-file", required=True, type=Path)
    parser.add_argument("--hec-token-file", type=Path)
    parser.add_argument("--search-url", default="https://127.0.0.1:18089")
    parser.add_argument("--hec-url", default="https://127.0.0.1:18088")
    args = parser.parse_args()
    try:
        search_url, hec_url = local_origin(args.search_url), local_origin(args.hec_url)
        with httpx.Client(base_url=search_url, verify=False, timeout=45,
                          headers={"Authorization": "Bearer " + args.search_token_file.read_text().strip()}) as search:
            if args.stage == "load":
                if args.hec_token_file is None:
                    raise ValueError("HEC token file is required for load")
                with httpx.Client(base_url=hec_url, verify=False, timeout=30,
                                  headers={"Authorization": "Splunk " + args.hec_token_file.read_text().strip()}) as hec:
                    result = run(args.stage, fixture=args.fixture, output=args.output, search=search, hec=hec)
            else:
                result = run(args.stage, fixture=args.fixture, output=args.output, search=search)
    except (OSError, ValueError, KeyError, httpx.HTTPError) as exc:
        diagnostic = {"status": "failed", "error_type": type(exc).__name__}
        if isinstance(exc, httpx.HTTPStatusError):
            diagnostic["http_status"] = str(exc.response.status_code)
            diagnostic["path"] = exc.request.url.path
        print(json.dumps(diagnostic))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
