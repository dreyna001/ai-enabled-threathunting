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

POLICY_VERSION = "1.5"
_SOURCE_FIELDS = ("index", "sourcetype", "_time", "_cd")
BUILTIN_FIELDS = frozenset({"_time", "_raw", "host", "source", "sourcetype", "index"})
ALLOWED_EVAL_FUNCTIONS = frozenset({
    "abs", "case", "ceil", "cidrmatch", "coalesce", "cos", "exact", "exp", "false", "floor", "if", "in",
    "isbool", "isint", "isnotnull", "isnull", "isnum", "isstr", "len", "like", "log", "lower", "ltrim", "match",
    "max", "min", "mvappend", "mvcount", "mvdedup", "mvfilter", "mvfind", "mvindex", "mvjoin", "mvmap",
    "mvsort", "mvzip", "now", "null", "nullif", "pow", "replace", "round", "rtrim", "sin", "split", "sqrt",
    "strftime", "strptime", "substr", "tan", "tonumber", "tostring", "trim", "true", "upper", "validate",
})
ALLOWED_STATS_FUNCTIONS = frozenset({
    "avg", "c", "count", "dc", "distinct_count", "earliest", "earliest_time", "estdc", "estdc_error",
    "first", "last", "latest", "latest_time", "list", "max", "mean", "median", "min", "mode", "range",
    "rate", "stdev", "stdevp", "sum", "sumsq", "values", "var", "varp",
})
_ALLOWED_COMMANDS = frozenset({"search", "where", "fields", "table", "stats", "timechart", "sort", "head", "dedup", "rename", "eval", "regex"})
_COMMAND = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\b(.*)$", re.DOTALL)
_SCOPE_FIELD = re.compile(r"(?i)(?<![A-Za-z0-9_])(?P<field>index|sourcetype)\b")
_SCOPE_PREDICATE = re.compile(r"(?i)(?P<field>index|sourcetype)\s*=\s*(?:\"(?P<double>[A-Za-z0-9_.:-]+)\"|'(?P<single>[A-Za-z0-9_.:-]+)'|(?P<bare>[A-Za-z0-9_.:-]+))(?=$|[\s|)])")
_NEGATED_SCOPE = re.compile(r"(?i)(?:\bNOT\s*(?:\(\s*)*|(?<![A-Za-z0-9_])-\s*)(?P<field>index|sourcetype)\b")
_INLINE_TIME = re.compile(r"(?i)(?:^|\s)(?:earliest|latest)\s*=")
_SEARCH_TOKEN = re.compile(r'''\(|\)|(?:[^\s()"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+''')
_QUOTED_TOKEN = r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'"
_FIELD_TOKEN = re.compile(_QUOTED_TOKEN + r'''|<=|>=|!=|<>|[(),=<>!]|[^\s(),=<>!"']+''')
_EXPRESSION_TOKEN = re.compile(_QUOTED_TOKEN + r"|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[A-Za-z_]\w*|[^\s]")


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


def _validate_field_references(parsed: ParsedSPL, discovered: frozenset[str]) -> None:
    """Check source fields and track aliases in command/expression order.

    Search compares fields to literal values; eval/where expressions can
    reference fields on either side and use single quotes for field names.
    Requested-field metadata cannot establish the validity of the SPL text.
    """
    known = set(discovered | BUILTIN_FIELDS)

    def field_name(token: str) -> str:
        if token.startswith(('"', "'")):
            if len(token) < 2 or token[-1] != token[0]:
                raise ValueError("field_syntax_not_supported")
            return re.sub(r'''\\(["'\\])''', r"\1", token[1:-1])
        return token

    def require(token: str, *, wildcard: bool = False) -> None:
        name = field_name(token)
        if name not in known and not (wildcard and any(fnmatchcase(field, name) for field in known)):
            raise ValueError("field_not_discovered")

    def expression(value: str, *, aggregate: bool = False) -> None:
        tokens = _EXPRESSION_TOKEN.findall(value)
        for index, token in enumerate(tokens):
            if token.startswith("'"):
                require(token)
            elif re.fullmatch(r"[A-Za-z_]\w*", token):
                if token.upper() in {"AND", "OR", "NOT", "XOR", "IN", "LIKE", "TRUE", "FALSE", "NULL"}:
                    continue
                if index + 1 < len(tokens) and tokens[index + 1] == "(":
                    if token.lower() not in ALLOWED_EVAL_FUNCTIONS and not (aggregate and token.lower() == "eval"):
                        raise ValueError("function_not_allowed")
                    continue  # Arguments are checked even inside nested calls.
                require(token)

    def aliases(source: str, target: str) -> tuple[set[str], set[str]]:
        if source.count("*") != target.count("*") or source.count("*") > 32:
            raise ValueError("field_syntax_not_supported")
        matched = {name for name in known if fnmatchcase(name, source)}
        renamed: set[str] = set()
        source_parts, target_parts = source.split("*"), target.split("*")
        for name in matched:
            cursor = len(source_parts[0])
            captures = []
            for index, part in enumerate(source_parts[1:], 1):
                suffix = "*".join(source_parts[index:])
                # Match each remaining suffix with the stdlib's bounded glob
                # implementation, avoiding an untrusted chain of regex .*
                end = next(end for end in range(len(name), cursor - 1, -1)
                           if fnmatchcase(name[end:], suffix))
                captures.append(name[cursor:end])
                cursor = end + len(part)
            renamed.add(target_parts[0] + "".join(value + suffix for value, suffix in zip(captures, target_parts[1:])))
        return matched, renamed

    def field_list(tokens: list[str], *, options: set[str] | None = None, sorting: bool = False,
                   wildcard: bool = False) -> None:
        position = 0
        while position < len(tokens):
            token = tokens[position]
            if (options and token.lower() in options and position + 2 < len(tokens)
                    and tokens[position + 1] == "="):
                position += 3
                continue
            position += 1
            if token in {",", "+", "-", "(", ")"} or (sorting and position == 1 and token.isdigit()):
                continue
            if sorting and token.lower() in {"asc", "desc", "sortby"}:
                continue
            if sorting and token.lower() in {"auto", "ip", "num", "str"} and position < len(tokens) and tokens[position] == "(":
                continue
            require(token.lstrip("+-"), wildcard=wildcard)

    aggregate_options = {"allnum", "partitions", "delim", "dedup_splitvals"}
    chart_options = aggregate_options | {"span", "minspan", "bins", "limit", "useother", "usenull", "cont", "fixedrange", "partial", "sep", "format", "nullstr", "otherstr", "start", "end", "aligntime"}
    for command, args in parsed.command_segments:
        matches = list(_FIELD_TOKEN.finditer(args))
        offset = 0
        for match in matches:
            if args[offset:match.start()].strip():
                raise ValueError("field_syntax_not_supported")
            offset = match.end()
        if args[offset:].strip():
            raise ValueError("field_syntax_not_supported")
        tokens = [match.group() for match in matches]
        if command == "search":
            for index, token in enumerate(tokens[:-1]):
                if tokens[index + 1] in {"=", "!=", "<>", "<", ">", "<=", ">="} or tokens[index + 1].upper() == "IN":
                    require(token)
        elif command == "where":
            expression(args)
        elif command == "eval":
            # Only top-level commas separate assignments; commas in function
            # arguments and quoted values cannot create an alias early.
            start = depth = 0
            for index, token in enumerate([*tokens, ","]):
                if token == "(":
                    depth += 1
                elif token == ")":
                    depth -= 1
                if depth < 0 or depth > 32:
                    raise ValueError("field_syntax_not_supported")
                if token != "," or depth:
                    continue
                assignment = tokens[start:index]
                if len(assignment) < 3 or assignment[1] != "=":
                    raise ValueError("field_syntax_not_supported")
                if not assignment[0].startswith(('"', "'")) and not re.fullmatch(r"[A-Za-z_]\w*", assignment[0]):
                    raise ValueError("field_syntax_not_supported")
                expression(" ".join(assignment[2:]))
                known.add(field_name(assignment[0]))
                start = index + 1
            if depth:
                raise ValueError("field_syntax_not_supported")
        elif command == "rename":
            renamed: set[str] = set()
            removed: set[str] = set()
            position = 0
            while position < len(tokens):
                if tokens[position] == ",":
                    position += 1
                    continue
                if position + 2 >= len(tokens) or tokens[position + 1].lower() != "as":
                    raise ValueError("field_syntax_not_supported")
                source, target = field_name(tokens[position]), field_name(tokens[position + 2])
                require(tokens[position], wildcard=True)
                matched, replacements = aliases(source, target)
                removed.update(matched)
                renamed.update(replacements)
                position += 3
            known.difference_update(removed)
            known.update(renamed)
        elif command in {"stats", "timechart"}:
            generated: set[str] = set()
            options = chart_options if command == "timechart" else aggregate_options
            position = 0
            while position < len(tokens):
                token = tokens[position]
                if token == ",":
                    position += 1
                    continue
                if token.lower() in options and position + 2 < len(tokens) and tokens[position + 1] == "=":
                    position += 3
                    continue
                if token.lower() == "by":
                    field_list(tokens[position + 1:], options=options)
                    break
                percentile = re.fullmatch(r"(?:p|perc|exactperc|upperperc)(\d{1,3})", token.lower())
                if token.lower() not in ALLOWED_STATS_FUNCTIONS and not (percentile and int(percentile[1]) <= 100):
                    raise ValueError("function_not_allowed")
                position += 1
                output = token
                wildcard_source: str | None = None
                if position < len(tokens) and tokens[position] == "(":
                    start = position + 1
                    depth = 1
                    position += 1
                    while position < len(tokens) and depth:
                        depth += (tokens[position] == "(") - (tokens[position] == ")")
                        position += 1
                    if depth:
                        raise ValueError("field_syntax_not_supported")
                    arguments = tokens[start:position - 1]
                    if len(arguments) == 1:
                        require(arguments[0], wildcard=True)
                        if "*" in field_name(arguments[0]):
                            wildcard_source = field_name(arguments[0])
                    else:
                        expression(" ".join(arguments), aggregate=True)
                    output = token + "(" + "".join(arguments) + ")"
                elif token.lower() not in {"count", "c"}:
                    raise ValueError("field_syntax_not_supported")
                aliased = position < len(tokens) and tokens[position].lower() == "as"
                if aliased:
                    if position + 1 >= len(tokens):
                        raise ValueError("field_syntax_not_supported")
                    output = field_name(tokens[position + 1])
                    position += 2
                if wildcard_source is not None:
                    if aliased:
                        generated.update(aliases(wildcard_source, output)[1])
                    else:
                        generated.update(token + "(" + name + ")" for name in known if fnmatchcase(name, wildcard_source))
                else:
                    generated.add(output)
            known.update(generated)
        elif command in {"table", "fields", "sort", "dedup"}:
            field_list(tokens, options={"keepevents", "keepempty", "consecutive"} if command == "dedup" else None,
                       sorting=command in {"sort", "dedup"}, wildcard=command in {"table", "fields"})
        elif command == "regex":
            if len(tokens) > 1 and tokens[1] in {"=", "!="}:
                require(tokens[0])
        elif command == "head" and not args.isdigit():
            predicate: list[str] = []
            position = 0
            while position < len(tokens):
                if tokens[position].lower() in {"limit", "keeplast", "null"} and position + 2 < len(tokens) and tokens[position + 1] == "=":
                    position += 3
                else:
                    predicate.append(tokens[position])
                    position += 1
            expression(" ".join(predicate))


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
                _validate_field_references(parsed, self.discovered_fields)
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
