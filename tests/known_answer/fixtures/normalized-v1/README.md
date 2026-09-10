# Normalized telemetry fixture v1

This is a synthetic, deliberately small investigation scenario, frozen before
running the model. It improves event consistency over the original lab fixture;
it does not reproduce enterprise event volumes or qualify production hunting.
The original 2,088-event dataset and its failed hunts remain unchanged.

The generator is [build_realistic_fixture.py](../../../../scripts/build_realistic_fixture.py).
It has no app/model dependency. To reproduce into a new directory:

```bash
python scripts/build_realistic_fixture.py --output /tmp/normalized-fixture-v1
python -m pytest tests/known_answer/test_realistic_fixture.py -q
```

The generator refuses to overwrite an existing directory. Changing generation
rules requires a separately versioned fixture and reviewed expectations. Do not
change data or expectations in response to a model's score.

## Scenario and limits

Three Windows workstations have fixed addresses and one interactive user each
over January 5–8, 2026 UTC. Each day contains a login/session, selected application
process starts and stops, a browser module load, and browser DNS/network events.
One local password failure precedes a successful login on ws-18. Addresses are
stable: no DHCP reassignment, NAT, multihoming, or clock skew is modeled. Collection
delay is 1–8 seconds. These restrictions describe this case, not universal telemetry.

On January 6, a process image on ws-17 has an advisory-listed HRsword.exe hash.
An administrative workstation also runs a file named HRsword.exe with a different
hash. Nearby browser activity belongs to a different process GUID. The records
establish file/process observations; they do not establish compromise, encryption,
authorization, intent, or attribution. Those judgments must not be manufactured
from the private scenario narrative. The HRsword hash comes from the preserved
[CISA AA23-352A advisory STIX](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a).
Other hashes are deterministic synthetic binary identifiers, not verified vendor
file hashes. No real executables or malware are included or executed.

The main stream has 689 events: 70 endpoint, 25 authentication, 297 DNS, and 297
network. This is selected normalized telemetry, not a complete Windows audit
stream. Parent processes may predate collection and are recorded by name only;
the data cannot establish an unobserved parent/child chain. Process IDs repeat
on later days, while process GUIDs identify individual lifetimes.

`network-outage.jsonl` is an alternative to `events.jsonl`, never an additional
load into the same indexes. Use a separate empty lab instance (with its own
loopback ports) to run this variant while preserving the complete dataset. It removes exactly 13 network records from ws-17
on January 6, 12:00–18:00 UTC. DNS and other sources continue. Its event contents
otherwise match the complete stream byte for byte. A separate trial must disclose
the known collector outage as environment context, or leave its cause unknown.
Missing connection records do not prove no connections occurred.

## Field and ingestion contract

These are custom `lab:normalized:*` records, not native Sysmon or Windows Event
Log exports. [Microsoft's event definitions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
provide the semantic distinction between process creation, image loading, and
process-associated activity. Field names here are explicitly normalized.

| Field | Meaning |
| --- | --- |
| HEC `host` | Workstation that originated the normalized event. |
| HEC `index`, `sourcetype`, `source` | Ingestion metadata; absent from the raw event body to avoid duplicate extraction. |
| HEC `time` / `event_time_utc` | The same event timestamp in epoch seconds / UTC ISO text. |
| `collected_time_utc` | Simulated collector receipt time. Splunk `_indextime` is the actual lab load time and may be months later. |
| `event_id` | Opaque unique event identity; no scenario, outcome, or IOC label. |
| `session_id`, `user` | Host-scoped authenticated interactive session and account. |
| `process_guid`, `process_id` | Stable lifetime identity and reusable host-local PID. |
| `image`, `process` | Executable path and its basename, including on module/DNS/network records. |
| `file_name`, `file_hash`, `hash_type` | On `process_start`, the executable image; on `image_load`, the loaded module identified by `image_loaded`. |
| `src_ip` | Stable originating workstation IP for endpoint-collected DNS/network activity. |
| `dns_query`, `answer_ip` | Requested A-record name and observed successful answer. |
| `dest_ip`, `dest_port`, `transport` | Observed outbound TCP connection destination. |

A module's file name need not equal its hosting process name. The validator
accepts that difference and rejects mismatches for a `process_start`, whose
contract identifies the same executable in both fields. This does not mean every
process/file mismatch in other schemas is impossible.

[Splunk 10.4 HEC formatting](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/get-data-with-http-event-collector/format-events-for-http-event-collector)
places `host`, `time`, `index`, and `sourcetype` beside `event`. Loading must preserve
that envelope and verify indexed metadata as scalar values against it. A raw-host
collision, duplicate extraction, missing field, delayed collection, or malformed
timestamp can occur in real pipelines; keep those as explicitly documented
robustness cases rather than silently cleaning the historical baseline.

## Evaluation isolation

Only event envelopes go to Splunk. `expectations.json`, manifest counts, outcome
text, and key-event IDs are evaluator inputs and must not enter a model request.
Analyst context can include source field semantics, inventory, declared collection
coverage, hunt scope, and the supplied advisory. Fixture provenance is public;
per-event answer labels are not.

The expected indicator observation is only one part of evaluation. Review whether
the report distinguishes filename matches from hash matches, cites each material
claim, preserves process identity, covers the relevant sources, and expresses
uncertainty. Retrieving/citing the expected event does not prove analytical success.
This assistant-authored fixture is not an independent holdout or analyst review.
