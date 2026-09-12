#!/usr/bin/env python3
"""Build a versioned normalized-telemetry lab fixture without calling the app/model.

The event stream and private expectations are separate outputs. See the fixture
README for the scenario, field semantics, limitations, and source references.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import random
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5


VERSION = "normalized-lab-20260909-v1"
START = datetime(2026, 1, 5, tzinfo=timezone.utc)
END = START + timedelta(days=4)
INVENTORY = {
    "ws-17.corp.example": {"ip": "10.40.8.17", "user": "CORP\\j.smith"},
    "ws-18.corp.example": {"ip": "10.40.8.18", "user": "CORP\\a.chen"},
    "ops-03.corp.example": {"ip": "10.40.9.3", "user": "CORP\\m.rivera"},
}
# Exact file indicator from the preserved CISA AA23-352A STIX, not a claim
# that these synthetic events were observed in a real incident.
ADVISORY_HASH = "0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549"
SOURCES = {kind: (f"th_real_v1_{kind}", f"lab:normalized:{kind}")
           for kind in ("endpoint", "auth", "dns", "network")}


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def identity(value: str) -> str:
    return str(uuid5(NAMESPACE_URL, VERSION + "/" + value))


def build_fixture() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Generate one fixed scenario; model outcomes never influence generation."""
    rng = random.Random(20260909)
    rows: list[dict[str, Any]] = []
    key_events: dict[str, str] = {}

    def event(kind: str, host: str, at: datetime, action: str, **fields: Any) -> str:
        event_id = identity("event/" + str(len(rows)))
        body = {"event_id": event_id, "event_time_utc": timestamp(at),
                "collected_time_utc": timestamp(at + timedelta(seconds=rng.randint(1, 8))),
                "action": action, **fields}
        index, sourcetype = SOURCES[kind]
        rows.append({"time": at.timestamp(), "host": host, "index": index,
                     "sourcetype": sourcetype, "source": "normalized-lab-collector", "event": body})
        return event_id

    for day in range(4):
        for number, (host, asset) in enumerate(INVENTORY.items()):
            login = START + timedelta(days=day, hours=8, minutes=number * 19 + rng.randint(0, 13),
                                      seconds=rng.randint(0, 59))
            logout = login + timedelta(hours=8, minutes=rng.randint(5, 49))
            session = identity(f"session/{day}/{host}")
            user = asset["user"]
            # A mistyped local interactive password followed by a successful login.
            if day == 1 and number == 1:
                event("auth", host, login - timedelta(seconds=19), "logon", user=user,
                      logon_type=2, result="failure", authentication_method="negotiate")
            event("auth", host, login, "logon", user=user, logon_type=2,
                  result="success", authentication_method="negotiate", session_id=session)
            event("auth", host, logout, "logoff", user=user, session_id=session, result="success")
            programs = [(r"C:\Program Files\Browser\browser.exe", "explorer.exe"),
                        (r"C:\Program Files\Office\wordproc.exe", "explorer.exe")]
            if host.startswith("ops"):
                programs.append((r"C:\AdminTools\HRsword.exe", "explorer.exe"))
            for ordinal, (image, parent) in enumerate(programs):
                guid = identity(f"process/{day}/{host}/{ordinal}")
                pid = 4100 + number * 100 + ordinal * 4  # IDs may recur on later days.
                begin = login + timedelta(seconds=31 + ordinal * 79 + rng.randint(0, 21))
                finish = logout - timedelta(seconds=30 + ordinal * 3)
                common = {"process_guid": guid, "process_id": pid, "image": image,
                          "process": PureWindowsPath(image).name, "user": user, "session_id": session}
                event("endpoint", host, begin, "process_start", **common, parent_process=parent,
                      command_line=f'"{image}"', file_name=PureWindowsPath(image).name,
                      hash_type="sha256", file_hash=hashlib.sha256(("lab-binary/" + image).encode()).hexdigest())
                event("endpoint", host, finish, "process_end", **common)
                if ordinal != 0:
                    continue
                module = r"C:\Windows\System32\winhttp.dll"
                event("endpoint", host, begin + timedelta(seconds=2), "image_load", **common,
                      image_loaded=module, file_name=PureWindowsPath(module).name,
                      hash_type="sha256", file_hash=hashlib.sha256(("lab-binary/" + module).encode()).hexdigest())
                at = begin + timedelta(minutes=4)
                while at < finish - timedelta(minutes=2):
                    domain, address = rng.choice([
                        ("portal.corp.example", "10.40.20.12"),
                        ("docs.vendor.example", "192.0.2.40"),
                        ("updates.vendor.example", "198.51.100.24"),
                    ])
                    dns_id = event("dns", host, at, "dns_query", **common, src_ip=asset["ip"],
                                   dns_query=domain, query_type="A", answer_ip=address, result="success")
                    net_id = event("network", host, at + timedelta(seconds=rng.randint(1, 4)),
                                   "connection", **common, src_ip=asset["ip"], dest_ip=address,
                                   dest_port=443, transport="tcp", direction="outbound", result="allowed")
                    if day == 1 and number == 0 and at.hour >= 13 and "nearby_browser_dns" not in key_events:
                        key_events.update(nearby_browser_dns=dns_id, nearby_browser_network=net_id)
                    at += timedelta(minutes=rng.randint(9, 31), seconds=rng.randint(0, 59))
            if day == 1 and number == 0:
                at = START + timedelta(days=1, hours=13, minutes=7, seconds=43)
                image = r"C:\ProgramData\Tools\HRsword.exe"
                common = {"process_guid": identity("process/advisory-observation"), "process_id": 5824,
                          "image": image, "process": "HRsword.exe", "user": user, "session_id": session}
                key_events["advisory_process"] = event(
                    "endpoint", host, at, "process_start", **common, parent_process="cmd.exe",
                    command_line=f'"{image}"', file_name="HRsword.exe", hash_type="sha256", file_hash=ADVISORY_HASH)
                key_events["advisory_process_end"] = event(
                    "endpoint", host, at + timedelta(minutes=11, seconds=26), "process_end", **common)

    rows.sort(key=lambda item: (item["time"], item["event"]["event_id"]))
    expectations = {
        "review_basis": "scenario defined before any model execution; assistant-authored, not independent analyst acceptance",
        "expected_event_ids": [key_events["advisory_process"]], "key_events": key_events,
        "supported": ["One observed process image hash matches the supplied advisory indicator.",
                      "Nearby browser DNS/network records have a different process GUID from that process."],
        "not_established": ["Ransomware execution, encryption, compromise, actor attribution, or operator intent.",
                            "That browser connections were made by HRsword.exe.",
                            "Authorization of either copy of HRsword.exe or a causal link from the failed login on ws-18."],
        "outage": {"host": "ws-17.corp.example", "source": "network",
                   "earliest_utc": "2026-01-06T12:00:00Z", "latest_utc": "2026-01-06T18:00:00Z",
                   "meaning": "Endpoint network collection unavailable; other telemetry continues. Absence does not establish no connections."},
    }
    return rows, expectations


def validate_fixture(rows: list[dict[str, Any]]) -> None:
    """Check this scenario's physical and collection contracts, not hunt success."""
    seen: set[str] = set()
    starts: dict[str, dict[str, Any]] = {}
    ends: dict[str, float] = {}
    sessions: dict[str, tuple[str, str, float]] = {}
    logoffs: dict[str, float] = {}
    allowed = {
        "event_id", "event_time_utc", "collected_time_utc", "action", "user", "logon_type",
        "result", "authentication_method", "session_id", "process_guid", "process_id", "image",
        "process", "parent_process", "command_line", "file_name", "hash_type", "file_hash",
        "image_loaded", "src_ip", "dns_query", "query_type", "answer_ip", "dest_ip", "dest_port",
        "transport", "direction",
    }
    for row in rows:
        body = row["event"]
        UUID(body["event_id"])
        if body["event_id"] in seen or set(body) - allowed:
            raise ValueError("duplicate event identity or undeclared/answer field")
        seen.add(body["event_id"])
        if set(row) != {"time", "host", "index", "sourcetype", "source", "event"}:
            raise ValueError("invalid HEC metadata")
        if row["host"] not in INVENTORY or (row["index"], row["sourcetype"]) not in SOURCES.values():
            raise ValueError("unknown host or source")
        when = datetime.fromisoformat(body["event_time_utc"])
        collected = datetime.fromisoformat(body["collected_time_utc"])
        if when.tzinfo is None or not START <= when < END or when.timestamp() != row["time"]:
            raise ValueError("event time and HEC time disagree or are outside the scenario")
        if collected.tzinfo is None or not when <= collected <= when + timedelta(seconds=8):
            raise ValueError("collection time violates the declared no-skew/maximum-delay contract")
        if body["user"] != INVENTORY[row["host"]]["user"]:
            raise ValueError("account is inconsistent with the declared session scenario")
        if "src_ip" in body and body["src_ip"] != INVENTORY[row["host"]]["ip"]:
            raise ValueError("source IP violates the declared stable address assignment")
        action = body["action"]
        kind = {"logon": "auth", "logoff": "auth", "process_start": "endpoint", "process_end": "endpoint",
                "image_load": "endpoint", "dns_query": "dns", "connection": "network"}.get(action)
        if kind is None or (row["index"], row["sourcetype"]) != SOURCES[kind]:
            raise ValueError("action and source disagree")
        if "file_hash" in body:
            value = body["file_hash"]
            if body.get("hash_type") != "sha256" or len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
                raise ValueError("invalid SHA-256 representation")
            target = body["image_loaded"] if action == "image_load" else body["image"]
            if body["file_name"] != PureWindowsPath(target).name:
                raise ValueError("hash target and file name disagree")
        if action == "process_start":
            guid = body["process_guid"]
            if guid in starts:
                raise ValueError("process GUID reused for multiple process creations")
            starts[guid] = row
        elif action == "process_end":
            guid = body["process_guid"]
            if guid in ends:
                raise ValueError("duplicate process termination")
            ends[guid] = row["time"]
        elif action == "logon" and body["result"] == "success":
            session = body["session_id"]
            if session in sessions:
                raise ValueError("session identity reused")
            sessions[session] = (row["host"], body["user"], row["time"])
        elif action == "logoff":
            if body["session_id"] in logoffs:
                raise ValueError("duplicate logoff")
            logoffs[body["session_id"]] = row["time"]
    for row in rows:
        body = row["event"]
        if "session_id" in body:
            session = sessions.get(body["session_id"])
            if session is None or session[:2] != (row["host"], body["user"]) or not session[2] <= row["time"] <= logoffs.get(body["session_id"], -1):
                raise ValueError("event is outside its declared authenticated session")
        if "process_guid" not in body:
            continue
        origin = starts.get(body["process_guid"])
        if origin is None or not origin["time"] <= row["time"] <= ends.get(body["process_guid"], -1):
            raise ValueError("event is outside its declared process lifetime")
        if row["host"] != origin["host"] or any(body[k] != origin["event"][k] for k in ("process_id", "image", "process", "user", "session_id")):
            raise ValueError("process identity changed during its lifetime")
        if body["process"] != PureWindowsPath(body["image"]).name:
            raise ValueError("process name and executable image disagree")
    lifetimes: dict[tuple[str, int], list[tuple[float, float]]] = {}
    for guid, origin in starts.items():
        lifetime = (origin["time"], ends[guid])
        key = (origin["host"], origin["event"]["process_id"])
        previous = lifetimes.setdefault(key, [])
        if any(lifetime[0] < stop and begin < lifetime[1] for begin, stop in previous):
            raise ValueError("two live processes share one host/PID")
        previous.append(lifetime)


def write_fixture(output: Path) -> dict[str, Any]:
    rows, expectations = build_fixture()
    validate_fixture(rows)
    outage = expectations["outage"]
    incomplete = [r for r in rows if not (
        r["host"] == outage["host"] and r["index"] == SOURCES["network"][0]
        and outage["earliest_utc"] <= r["event"]["event_time_utc"] < outage["latest_utc"])]
    validate_fixture(incomplete)
    output.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, events in (("events.jsonl", rows), ("network-outage.jsonl", incomplete)):
        content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in events).encode()
        (output / name).write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    manifest = {"fixture_version": VERSION, "earliest_utc": timestamp(START), "latest_utc": timestamp(END),
                "content_hashes": hashes, "event_count": len(rows), "outage_event_count": len(incomplete),
                "counts_by_index": dict(Counter(r["index"] for r in rows)), "inventory": INVENTORY,
                "outage_excluded_count": len(rows) - len(incomplete),
                "advisory_indicator": {"file_name": "HRsword.exe", "sha256": ADVISORY_HASH,
                    "source_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"}}
    (output / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    (output / "expectations.json").write_bytes((json.dumps(expectations, indent=2) + "\n").encode())
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(write_fixture(parser.parse_args().output), indent=2))
