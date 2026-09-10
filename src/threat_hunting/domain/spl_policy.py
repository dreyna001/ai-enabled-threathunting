"""Deterministic, fail-closed SPL validation for bounded hunt queries."""

from __future__ import annotations

import hashlib
import json
import re
from fnmatch import fnmatchcase
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Sequence
from types import MappingProxyType
from uuid import uuid4

from threat_hunting.domain.common import ensure_utc
from threat_hunting.domain.contracts import QUERY_RESULT_LIMITS, EnforcedQueryLimits, QueryProposal, QueryValidationResult

POLICY_VERSION = "1.4"
_SOURCE_FIELDS = ("index", "sourcetype", "_time", "_cd")
BUILTIN_FIELDS = frozenset({"_time", "_raw", "host", "source", "sourcetype", "index"})
_ALLOWED_COMMANDS = frozenset({"search", "where", "fields", "table", "stats", "timechart", "sort", "head", "dedup", "rename", "eval", "regex"})
_COMMAND = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\b(.*)$", re.DOTALL)
_SCOPE_FIELD = re.compile(r"(?i)(?<![A-Za-z0-9_])(?P<field>index|sourcetype)\b")
_SCOPE_PREDICATE = re.compile(r"(?i)(?P<field>index|sourcetype)\s*=\s*(?:\"(?P<double>[A-Za-z0-9_.:-]+)\"|'(?P<single>[A-Za-z0-9_.:-]+)'|(?P<bare>[A-Za-z0-9_.:-]+))(?=$|[\s|)])")
_NEGATED_SCOPE = re.compile(r"(?i)(?:\bNOT\s*(?:\(\s*)*|(?<![A-Za-z0-9_])-\s*)(?P<field>index|sourcetype)\b")
_INLINE_TIME = re.compile(r"(?i)(?:^|\s)(?:earliest|latest)\s*=")
_SEARCH_TOKEN = re.compile(r'''\(|\)|(?:[^\s()"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+''')


@dataclass(frozen=True, slots=True)
class ParsedSPL:
    """Normalized SPL command segments used by policy and query strategy."""

    normalized: str
    command_segments: tuple[tuple[str, str], ...]

    @property
    def aggregates_events(self) -> bool:
        """Identify event-reducing commands in the supported SPL subset."""
        return any(command in {"stats", "timechart"} for command, _ in self.command_segments)


def parse_spl(value: str) -> ParsedSPL:
    """Parse a small allow-listed SPL pipeline and reject ambiguous syntax."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("SPL must be non-empty")
    if len(value) > 20_000 or "`" in value or "[" in value or "]" in value or "\x00" in value:
        raise ValueError("SPL contains unsupported syntax")
    parts = [part.strip() for part in value.split("|")]
    if any(not part for part in parts):
        raise ValueError("SPL contains an empty command")
    segments: list[tuple[str, str]] = []
    for index, part in enumerate(parts):
        if index == 0 and part.startswith("("):
            # Like index=..., a grouped first expression is an implicit
            # search. The API requires its explicit command in normalized SPL.
            segments.append(("search", part))
            continue
        match = _COMMAND.match(part)
        if match is None:
            raise ValueError("SPL command is malformed")
        command, args = match.group(1).casefold(), match.group(2).strip()
        if index == 0 and command != "search":
            # Implicit searches begin with index=... rather than a command.
            if "=" in part:
                command, args = "search", part
            else:
                raise ValueError("SPL must begin with search")
        if command not in _ALLOWED_COMMANDS:
            raise ValueError(f"SPL command is not allowed: {command}")
        segments.append((command, args))
    normalized = " | ".join(f"{command} {args}".rstrip() for command, args in segments)
    return ParsedSPL(normalized=normalized, command_segments=tuple(segments))


def _preserve_raw_source_fields(parsed: ParsedSPL) -> str:
    """Retain native provenance through raw projections without changing matches."""
    if parsed.aggregates_events:
        return parsed.normalized
    segments = []
    for command, args in parsed.command_segments:
        fields = re.findall(r"[^\s,]+", args)
        modified = []
        if command == "fields" and args.startswith("-"):
            modified = [field.lstrip("-").strip("\"'") for field in fields if field != "-"]
        elif command in {"table", "fields"}:
            selected = {field.strip("\"'") for field in fields}
            args += "".join(" " + field for field in _SOURCE_FIELDS if field not in selected)
        elif command == "eval":
            modified = re.findall(r"(?:^|,)\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*=", args)
        elif command == "rename":
            modified = [field.strip("\"'") for pair in re.findall(r"(\S+)\s+as\s+(\S+)", args, re.IGNORECASE) for field in pair]
        if any(fnmatchcase(field, pattern) for field in _SOURCE_FIELDS for pattern in modified):
            raise ValueError("source_metadata_modified")
        segments.append(f"{command} {args}".rstrip())
    return " | ".join(segments)


def _scope_values(value: str, field: str) -> tuple[set[str], bool]:
    """Extract exact positive scope predicates and flag every other form."""

    values: set[str] = set()
    invalid = any(
        match.group("field").casefold() == field
        for match in _NEGATED_SCOPE.finditer(value)
    )
    for occurrence in _SCOPE_FIELD.finditer(value):
        if occurrence.group("field").casefold() != field:
            continue
        predicate = _SCOPE_PREDICATE.match(value, occurrence.start())
        if predicate is None:
            invalid = True
            continue
        selected = predicate.group("double") or predicate.group("single") or predicate.group("bare")
        values.add(selected)
    return values, invalid


def _source_branches(value: str) -> set[tuple[str | None, str | None]]:
    """Prove positive source bounds using search's OR-before-AND precedence.

    Other filters are treated as potentially true; this proves source scope,
    not whether arbitrary event predicates will match. None means unbounded.
    """
    tokens: list[str] = []
    offset = 0
    while offset < len(value):
        if value[offset].isspace():
            offset += 1
            continue
        match = _SCOPE_PREDICATE.match(value, offset) or _SEARCH_TOKEN.match(value, offset)
        if match is None or len(tokens) >= 2000:
            raise ValueError("unsupported source expression")
        tokens.append(match.group())
        offset = match.end()
    position = 0

    def atom(depth: int) -> set[tuple[str | None, str | None]]:
        nonlocal position
        if position >= len(tokens) or depth > 32:
            raise ValueError("incomplete or deeply nested source expression")
        token = tokens[position]
        position += 1
        if token == "NOT":
            start = position
            atom(depth + 1)
            if any(_SCOPE_PREDICATE.fullmatch(item) for item in tokens[start:position]):
                raise ValueError("negated source expression")
            return {(None, None)}
        if token == "(":
            branches = conjunction(depth + 1)
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unbalanced source expression")
            position += 1
            return branches
        if token in {"AND", "OR", "XOR", ")"}:
            raise ValueError("unexpected Boolean operator")
        predicate = _SCOPE_PREDICATE.fullmatch(token)
        if predicate is None:
            return {(None, None)}
        selected = predicate.group("double") or predicate.group("single") or predicate.group("bare")
        return {(selected, None)} if predicate.group("field").casefold() == "index" else {(None, selected)}

    def disjunction(depth: int) -> set[tuple[str | None, str | None]]:
        nonlocal position
        branches = atom(depth)
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            branches |= atom(depth)
            if len(branches) > 128:
                raise ValueError("too many source alternatives")
        return branches

    def conjunction(depth: int) -> set[tuple[str | None, str | None]]:
        nonlocal position
        branches = disjunction(depth)
        while position < len(tokens) and tokens[position] != ")":
            if tokens[position] == "AND":
                position += 1
            right = disjunction(depth)
            combined: set[tuple[str | None, str | None]] = set()
            for left_index, left_source in branches:
                for right_index, right_source in right:
                    if (left_index is not None and right_index is not None and left_index != right_index
                            or left_source is not None and right_source is not None and left_source != right_source):
                        continue
                    combined.add((left_index or right_index, left_source or right_source))
                    if len(combined) > 128:
                        raise ValueError("too many source alternatives")
            branches = combined
        return branches

    branches = conjunction(0)
    if position != len(tokens):
        raise ValueError("unexpected closing parenthesis")
    return branches


def source_pairs(spl: str) -> frozenset[tuple[str, str]]:
    """Return the satisfiable exact source pairs, never a metadata cross-product."""
    expression = parse_spl(spl).command_segments[0][1]
    if any(_scope_values(expression, field)[1] for field in ("index", "sourcetype")):
        raise ValueError("source scope is not exact")
    branches = _source_branches(expression)
    if not branches or any(index is None or source is None for index, source in branches):
        raise ValueError("source scope is contradictory or unbounded")
    return frozenset((index, source) for index, source in branches if index is not None and source is not None)


class SPLPolicy:
    """Immutable execution policy pinned to discovery and approved scope."""

    def __init__(
        self,
        *,
        discovered_indexes: set[str],
        discovered_sourcetypes: set[str],
        discovered_fields: set[str],
        approved_indexes: set[str],
        approved_sourcetypes: set[str],
        approved_earliest_utc: datetime,
        approved_latest_utc: datetime,
        connection_id: str,
        execution_config_snapshot_id: str,
        max_results_by_mode: dict[str, int] | None = None,
        max_bytes: int = 262_144_000,
        timeout_seconds: int = 120,
    ) -> None:
        self.discovered_indexes = frozenset(discovered_indexes)
        self.discovered_sourcetypes = frozenset(discovered_sourcetypes)
        self.discovered_fields = frozenset(discovered_fields)
        self.approved_indexes = frozenset(approved_indexes)
        self.approved_sourcetypes = frozenset(approved_sourcetypes)
        self.approved_earliest_utc = ensure_utc(approved_earliest_utc)
        self.approved_latest_utc = ensure_utc(approved_latest_utc)
        self.connection_id = connection_id
        self.execution_config_snapshot_id = execution_config_snapshot_id
        self.max_results_by_mode = MappingProxyType(max_results_by_mode or {mode.value: limit for mode, limit in QUERY_RESULT_LIMITS.items()})
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    def validate(self, proposal: QueryProposal, *, open_question_ids: Sequence[str] | None = None) -> QueryValidationResult:
        """Return a structured allow/reject decision without executing SPL."""

        reasons: list[str] = []
        try:
            parsed = parse_spl(proposal.spl)
            normalized = parsed.normalized
            scope_expression = parsed.command_segments[0][1]
        except ValueError:
            normalized = " ".join(proposal.spl.split()) or "invalid"
            scope_expression = proposal.spl
            reasons.append("spl_not_allowed")
        if "spl_not_allowed" not in reasons:
            try:
                normalized = _preserve_raw_source_fields(parsed)
            except ValueError as exc:
                reasons.append(str(exc))
        spl_indexes, invalid_index_scope = _scope_values(scope_expression, "index")
        spl_sourcetypes, invalid_sourcetype_scope = _scope_values(scope_expression, "sourcetype")
        try:
            branches = _source_branches(scope_expression)
            if not branches:
                reasons.append("source_scope_contradictory")
            elif any(index is None or source is None for index, source in branches):
                reasons.append("source_scope_unbounded")
        except ValueError:
            reasons.append("source_expression_not_supported")
        if invalid_index_scope:
            reasons.append("index_scope_not_exact")
        if invalid_sourcetype_scope:
            reasons.append("sourcetype_scope_not_exact")
        if not proposal.indexes or not spl_indexes:
            reasons.append("index_scope_missing")
        elif spl_indexes != set(proposal.indexes):
            reasons.append("index_metadata_mismatch")
        if not proposal.sourcetypes or not spl_sourcetypes:
            reasons.append("sourcetype_scope_missing")
        elif spl_sourcetypes != set(proposal.sourcetypes):
            reasons.append("sourcetype_metadata_mismatch")
        if _INLINE_TIME.search(proposal.spl):
            reasons.append("inline_time_not_allowed")
        if open_question_ids is not None and proposal.question_id not in open_question_ids:
            reasons.append("question_not_open")
        if not set(proposal.indexes).issubset(self.approved_indexes & self.discovered_indexes):
            reasons.append("index_outside_scope")
        if not set(proposal.sourcetypes).issubset(self.approved_sourcetypes & self.discovered_sourcetypes):
            reasons.append("sourcetype_outside_scope")
        if not set(proposal.requested_fields).issubset(self.discovered_fields | BUILTIN_FIELDS):
            reasons.append("field_not_discovered")
        if proposal.earliest_utc < self.approved_earliest_utc or proposal.latest_utc > self.approved_latest_utc:
            reasons.append("time_outside_scope")
        cap = self.max_results_by_mode.get(proposal.result_mode.value, 0)
        if proposal.max_results > cap:
            reasons.append("result_limit_exceeded")
        allowed = not reasons
        material = {
            "normalized_spl": normalized,
            "connection_id": self.connection_id,
            "execution_config_snapshot_id": self.execution_config_snapshot_id,
            "earliest_utc": proposal.earliest_utc.isoformat(),
            "latest_utc": proposal.latest_utc.isoformat(),
            "max_results": proposal.max_results,
            "max_bytes": self.max_bytes,
            "timeout_seconds": self.timeout_seconds,
            "policy_version": POLICY_VERSION,
        }
        cache_key = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if allowed else None
        return QueryValidationResult(
            schema_version="1.0",
            query_id=uuid4(),
            allowed=allowed,
            normalized_spl=normalized,
            earliest_utc=proposal.earliest_utc,
            latest_utc=proposal.latest_utc,
            cache_key=cache_key,
            reason_codes=list(dict.fromkeys(reasons)),
            enforced_limits=EnforcedQueryLimits(max_results=min(proposal.max_results, max(cap, 1)), max_bytes=self.max_bytes, timeout_seconds=self.timeout_seconds),
            query_policy_version=POLICY_VERSION,
        )


__all__ = ["BUILTIN_FIELDS", "POLICY_VERSION", "ParsedSPL", "SPLPolicy", "parse_spl"]
