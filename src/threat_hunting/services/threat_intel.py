"""Deterministic extraction of queryable indicators from analyst-supplied STIX."""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Mapping, Sequence

from threat_hunting.services.evidence import _flatten_scalar_values

_HASH_PATTERNS = {
    "sha256": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    "sha1": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"),
    "md5": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"),
}
_FILE_NAME_PATTERN = re.compile(r"file:name\s*=\s*'([^']+)'", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE)


def intelligence_sources(hunt_id: str, text: str) -> list[dict[str, str]]:
    """Identify the actual supplied advisory field without inventing a document."""
    if not text.strip():
        return []
    return [{
        "source_id": "analyst-intelligence:" + hashlib.sha256((hunt_id + "\0" + text).encode()).hexdigest(),
        "kind": "analyst_supplied_context", "content_field": "threat_intelligence",
        "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }]


def validate_intelligence_refs(refs: Any, sources: Sequence[Mapping[str, Any]]) -> None:
    """Reject references that do not resolve to application-provided sources."""
    allowed = {source["source_id"] for source in sources}
    if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in allowed for ref in refs):
        raise ValueError("plan intelligence reference is not among the supplied sources")


def extract_advisory_iocs(text: str, *, limit: int = 50) -> dict[str, list[str]]:
    """Return bounded, queryable IOCs from STIX JSON or supplied indicator text.

    Only indicator patterns are read from a valid STIX bundle.  Plain text is
    accepted to support analyst-supplied context, but is treated as advisory
    context rather than observed environment evidence.
    """

    patterns: list[str] = []
    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError:
        patterns.append(text)
    else:
        if isinstance(document, dict) and isinstance(document.get("objects"), list):
            patterns.extend(
                str(item["pattern"])
                for item in document["objects"]
                if isinstance(item, dict)
                and item.get("type") == "indicator"
                and isinstance(item.get("pattern"), str)
            )
        else:
            patterns.append(text)
    source = "\n".join(patterns)

    def values(pattern: re.Pattern[str]) -> list[str]:
        return list(dict.fromkeys(match.group(0).upper() for match in pattern.finditer(source)))[:limit]

    def captured(pattern: re.Pattern[str]) -> list[str]:
        return list(dict.fromkeys(match.group(1) for match in pattern.finditer(source)))[:limit]

    return {
        "sha256": values(_HASH_PATTERNS["sha256"]),
        "sha1": values(_HASH_PATTERNS["sha1"]),
        "md5": values(_HASH_PATTERNS["md5"]),
        "file_names": captured(_FILE_NAME_PATTERN),
        "domains": captured(_DOMAIN_PATTERN),
    }


def query_ioc_context(text: str) -> dict[str, list[str]]:
    """Supply exact indicator values without implying telemetry enum spellings."""

    extracted = extract_advisory_iocs(text)
    return {
        "file_hashes": list(dict.fromkeys(value for algorithm in ("sha256", "sha1", "md5") for value in extracted[algorithm])),
        "file_names": extracted["file_names"],
        "domains": extracted["domains"],
    }


def compare_advisory_iocs(
    selected_result: Any, advisory_iocs: Mapping[str, list[str]],
) -> dict[str, Any]:
    """Compare complete observed scalar literals with the extracted IOC lists.

    Hexadecimal hash comparisons ignore case; names/domains use exact literal
    equality. This does not evaluate STIX pattern logic, infer field semantics,
    or establish maliciousness. An empty hash list means no comparable literal
    was supplied, not an observed nonmatching hash. Retained data is unchanged.
    """
    values = list(dict.fromkeys(value for value in _flatten_scalar_values(selected_result) if isinstance(value, str)))
    hashes = {value.upper() for value in advisory_iocs["file_hashes"]}
    return {
        "hash_literals": [
            {"observed_value": value, "matches_extracted_advisory_hash": value.upper() in hashes}
            for value in values if any(pattern.fullmatch(value) for pattern in _HASH_PATTERNS.values())
        ],
        "matched_file_name_literals": [value for value in values if value in advisory_iocs["file_names"]],
        "matched_domain_literals": [value for value in values if value in advisory_iocs["domains"]],
    }
