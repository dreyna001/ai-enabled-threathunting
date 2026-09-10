"""Report drafts, secure PDF rendering, and owner-scoped report access.

The module deliberately keeps persistence behind a small repository protocol.
The SQL implementation uses the ``reports`` table from :mod:`services.schema`,
while tests and the application composition root may provide a transactionally
equivalent repository.  No report text is ever treated as HTML or as a URL.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import textwrap
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from threat_hunting.domain.contracts import HuntPlan
from threat_hunting.domain.errors import Validation
from threat_hunting.services.evidence import evidence_time_bounds, query_source_coverage

from sqlalchemy import text


REQUIRED_SECTIONS: tuple[str, ...] = (
    "hypothesis",
    "objective_and_scope",
    "data_sources_used",
    "findings",
    "selected_evidence",
    "entities",
    "timeline",
    "coverage_and_limitations",
    "conclusion_and_disposition",
    "query_appendix",
)
_RAW_RESULT_KEYS = {"raw_results", "raw_result_set", "full_raw_results", "result_batches"}
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class ReportError(RuntimeError):
    """Base class for report workflow failures."""


class ReportNotFound(ReportError):
    """The report does not exist or is not owned by the caller."""


class ReportForbidden(ReportError):
    """The caller is not allowed to access the report or evidence."""


class ReportConflict(ReportError):
    """An optimistic-concurrency version is stale."""


class ReportLocked(ReportError):
    """A finalized report cannot be changed."""


class ReportValidationError(ReportError):
    """Report content is incomplete or references unavailable artifacts."""


class ReportRenderError(ReportError):
    """PDF generation failed before a complete artifact was persisted."""


@dataclass(frozen=True, slots=True)
class ReportPreview:
    hunt_id: str
    report_id: str
    version: int
    state: str
    content: dict[str, Any]
    html: str


@dataclass(frozen=True, slots=True)
class FinalizedReport:
    hunt_id: str
    report_id: str
    version: int
    state: str
    pdf_sha256: str
    pdf_path: str
    finalized_at_utc: datetime


@dataclass(frozen=True, slots=True)
class DownloadedArtifact:
    content: bytes
    media_type: str
    filename: str


class ReportRepository(Protocol):
    """Persistence contract used by :class:`ReportService`.

    Implementations must apply the owner and hunt predicates in the database,
    not merely in a caller, and ``update_draft``/``finalize`` must be atomic.
    """

    def get_report(self, *, hunt_id: str, owner_id: str) -> Mapping[str, Any] | None: ...

    def update_draft(
        self, *, hunt_id: str, owner_id: str, expected_version: int, content: dict[str, Any]
    ) -> Mapping[str, Any] | None: ...

    def finalize(
        self,
        *,
        hunt_id: str,
        owner_id: str,
        expected_version: int,
        content: dict[str, Any],
        pdf_path: str,
        pdf_sha256: str,
        finalized_at_utc: datetime,
    ) -> Mapping[str, Any] | None: ...


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _value(record: Mapping[str, Any], key: str, default: Any = None) -> Any:
    return record.get(key, default)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_filename(value: str, *, suffix: str) -> str:
    cleaned = _SAFE_FILENAME.sub("-", value.strip()).strip(".-") or "report"
    return f"{cleaned[:120]}{suffix}"


def _as_text(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _timestamp(value: Any, display_timezone: str) -> str:
    """Display UTC and configured local time, with both timezone labels."""

    if value in (None, "unknown"):
        return "unknown"
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return html.escape(value)
    elif isinstance(value, datetime):
        parsed = value
    else:
        return html.escape(_as_text(value))
    utc_value = _utc(parsed)
    local = utc_value.astimezone(ZoneInfo(display_timezone))
    utc_text = utc_value.isoformat().replace("+00:00", "Z")
    return f"{html.escape(utc_text)} (UTC); {html.escape(local.isoformat())} ({html.escape(display_timezone)})"


def _list_text(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise ReportValidationError("report list fields must be arrays")
    return [_as_text(item) for item in values]


def _normalize_content(content: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(content, Mapping):
        raise ReportValidationError("report content must be an object")
    normalized = json.loads(json.dumps(content, ensure_ascii=False, default=str))
    if _RAW_RESULT_KEYS.intersection(normalized):
        raise ReportValidationError("full raw query results cannot be included in a report")
    if len(_json_bytes(normalized)) > 5 * 1024 * 1024:
        raise ReportValidationError("report content exceeds the 5 MiB input limit")
    return normalized


def validate_report_content(
    content: Mapping[str, Any],
    *,
    available_finding_ids: set[str] | None = None,
    available_evidence_ids: set[str] | None = None,
    available_query_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Validate required sections and citation references deterministically."""

    normalized = _normalize_content(content)
    # Canonical content stores the section values in fields such as
    # ``finding_ids``; section aliases make the renderer/API pleasant to use.
    aliases = {
        "findings": "finding_ids",
        "selected_evidence": "evidence_ids",
        "coverage_and_limitations": "coverage",
        "conclusion_and_disposition": "conclusion",
    }
    missing: list[str] = []
    for section in REQUIRED_SECTIONS:
        key = aliases.get(section, section)
        if key not in normalized:
            missing.append(section)
    if missing:
        raise ReportValidationError(f"missing required report sections: {', '.join(missing)}")
    for key in ("hypothesis", "objective_and_scope", "conclusion", "disposition"):
        if not isinstance(normalized.get(key), str) or not normalized[key].strip():
            raise ReportValidationError(f"report section {key!r} must contain text")
    for key in ("data_sources_used", "finding_ids", "evidence_ids", "query_ids", "entities", "timeline", "coverage", "limitations", "query_appendix"):
        if not isinstance(normalized.get(key), list):
            raise ReportValidationError(f"report section {key!r} must be an array")

    def check_ids(key: str, available: set[str] | None) -> None:
        if available is None:
            return
        unknown = {str(value) for value in normalized[key]} - available
        if unknown:
            raise ReportValidationError(f"report references unavailable {key}: {sorted(unknown)}")

    check_ids("finding_ids", available_finding_ids)
    check_ids("evidence_ids", available_evidence_ids)
    check_ids("query_ids", available_query_ids)
    if "question_answers" in normalized:
        answers = normalized["question_answers"]
        if not isinstance(answers, list):
            raise ReportValidationError("question_answers must be an array")
        for answer in answers:
            if (not isinstance(answer, Mapping)
                    or any(not isinstance(answer.get(key), str) or not answer[key].strip() for key in ("question_id", "question", "summary"))
                    or any(not isinstance(answer.get(key), list) or not all(isinstance(value, str) and value.strip() for value in answer[key]) for key in ("finding_ids", "limitations"))
                    or not (answer["finding_ids"] or answer["limitations"])):
                raise ReportValidationError("question answers require a summary and finding references or limitations")
            coverage = answer.get("lead_coverage", [])
            if not isinstance(coverage, list) or any(
                not isinstance(lead, dict) or set(lead) != {"lead_evidence_ids", "identity_fields", "finding_ids", "limitation"}
                or not isinstance(lead["lead_evidence_ids"], list) or not lead["lead_evidence_ids"]
                or any(not isinstance(value, str) or not value.strip() for value in lead["lead_evidence_ids"])
                or not isinstance(lead["identity_fields"], dict)
                or any(not isinstance(key, str) or not isinstance(value, str) or not value.strip() for key, value in lead["identity_fields"].items())
                or not isinstance(lead["finding_ids"], list)
                or any(value not in answer["finding_ids"] for value in lead["finding_ids"])
                or (lead["limitation"] is not None and (not isinstance(lead["limitation"], str) or not lead["limitation"].strip()))
                or (not lead["finding_ids"] and not lead["limitation"])
                for lead in coverage
            ):
                raise ReportValidationError("question lead coverage requires observed identity fields and findings or a limitation")
            if available_finding_ids is not None and not set(answer["finding_ids"]).issubset(available_finding_ids):
                raise ReportValidationError("question answer references unavailable findings")
    if str(normalized.get("disposition")) == "supported" and not normalized["evidence_ids"]:
        raise ReportValidationError("supported reports require retained evidence citations")
    for entry in normalized["query_appendix"]:
        if not isinstance(entry, Mapping):
            raise ReportValidationError("query appendix entries must be objects")
        required = {"query_id", "spl", "purpose", "indexes", "earliest_utc", "latest_utc", "execution_timestamp_utc", "splunk_job_id", "result_count", "status", "errors_or_truncation"}
        absent = required.difference(entry)
        if absent:
            raise ReportValidationError(f"query appendix entry missing: {', '.join(sorted(absent))}")
        # Exact UTC bounds are retained; reject naive timestamps rather than
        # silently changing the search range in a report.
        for key in ("earliest_utc", "latest_utc", "execution_timestamp_utc"):
            try:
                _utc(datetime.fromisoformat(str(entry[key]).replace("Z", "+00:00")))
            except (TypeError, ValueError) as exc:
                raise ReportValidationError(f"query appendix {key} must be an RFC3339 timestamp") from exc
    return normalized


def render_report_html(content: Mapping[str, Any], *, display_timezone: str = "UTC") -> str:
    """Render escaped report content using the bundled static template."""

    try:
        ZoneInfo(display_timezone)
    except ZoneInfoNotFoundError as exc:
        raise ReportValidationError("display timezone is not a valid IANA timezone") from exc
    content = validate_report_content(content)
    esc = lambda value: html.escape(_as_text(value), quote=True)

    def list_items(values: Sequence[Any]) -> str:
        return "".join(f"<li>{esc(item)}</li>" for item in values) or "<li>None recorded</li>"

    findings = content["findings"] if "findings" in content else content["finding_ids"]
    evidence = content.get("selected_evidence", content["evidence_ids"])
    entities = content["entities"]
    timeline_rows: list[str] = []
    for entry in content["timeline"]:
        if isinstance(entry, Mapping):
            timeline_rows.append(
                f"<li><strong>{_timestamp(entry.get('time_utc'), display_timezone)}</strong>: {esc(entry.get('description'))}</li>"
            )
        else:
            timeline_rows.append(f"<li>{esc(entry)}</li>")
    appendix_rows: list[str] = []
    for entry in content["query_appendix"]:
        appendix_rows.append(
            "<article class=\"query\">"
            f"<h3>{esc(entry['query_id'])}</h3>"
            f"<pre>{esc(entry['spl'])}</pre>"
            f"<p><b>Purpose:</b> {esc(entry['purpose'])}<br>"
            f"<b>Indexes:</b> {esc(entry['indexes'])}<br>"
            f"<b>UTC bounds:</b> {esc(entry['earliest_utc'])} to {esc(entry['latest_utc'])}<br>"
            f"<b>Executed:</b> {_timestamp(entry['execution_timestamp_utc'], display_timezone)}<br>"
            f"<b>Splunk job:</b> {esc(entry['splunk_job_id'])}; <b>Result count:</b> {esc(entry['result_count'])}; <b>Status:</b> {esc(entry['status'])}<br>"
            f"<b>Errors/truncation:</b> {esc(entry['errors_or_truncation'])}</p></article>"
        )
    sections = {
        "hypothesis": f"<p>{esc(content['hypothesis'])}</p>",
        "objective": f"<p>{esc(content['objective_and_scope'])}</p>",
        "sources": f"<ul>{list_items(content['data_sources_used'])}</ul>",
        "findings": f"<ul>{list_items(findings)}</ul>" + (
            "<h3>Approved question answers</h3>" + "".join(
                f"<ul>{list_items(_question_answer_text(answer))}</ul>"
                for answer in content["question_answers"]
            )
            if "question_answers" in content else ""
        ),
        "evidence": f"<ul>{list_items(evidence)}</ul>",
        "entities": f"<ul>{list_items(entities)}</ul>",
        "timeline": f"<ul>{''.join(timeline_rows) or '<li>None recorded</li>'}</ul>",
        "coverage": f"<h3>Coverage</h3><ul>{list_items(content['coverage'])}</ul><h3>Limitations</h3><ul>{list_items(content['limitations'])}</ul>",
        "conclusion": f"<p>{esc(content['conclusion'])}</p><p><b>Disposition:</b> {esc(content['disposition'])}</p>",
        "appendix": "".join(appendix_rows) or "<p>No queries were executed.</p>",
    }
    template_path = Path(__file__).parents[1] / "templates" / "report.html"
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError:
        template = "<!doctype html><html><body>{{HYPOTHESIS}}</body></html>"
    replacements = {
        "{{HYPOTHESIS}}": sections["hypothesis"], "{{OBJECTIVE}}": sections["objective"],
        "{{SOURCES}}": sections["sources"], "{{FINDINGS}}": sections["findings"],
        "{{EVIDENCE}}": sections["evidence"], "{{ENTITIES}}": sections["entities"],
        "{{TIMELINE}}": sections["timeline"], "{{COVERAGE}}": sections["coverage"],
        "{{CONCLUSION}}": sections["conclusion"], "{{APPENDIX}}": sections["appendix"],
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template


class SecureWeasyPrintRenderer:
    """Render only generated HTML and deny every URL/local-file fetch."""

    def render(self, html_document: str) -> bytes:
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ReportRenderError("WeasyPrint is required for PDF generation") from exc

        def deny_fetch(url: str, *args: Any, **kwargs: Any) -> Any:
            raise ReportRenderError("external and local PDF resources are disabled")

        try:
            document = HTML(string=html_document, base_url=None, url_fetcher=deny_fetch)
            pdf = document.write_pdf()
        except ReportError:
            raise
        except Exception as exc:  # renderer errors are resumable report failures
            raise ReportRenderError("secure PDF rendering failed") from exc
        if not isinstance(pdf, bytes) or not pdf.startswith(b"%PDF"):
            raise ReportRenderError("renderer did not return a complete PDF")
        return pdf


class FileArtifactStore:
    """Atomic PDF storage confined to one configured persistent directory."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        if path != self.root and self.root not in path.parents:
            raise ReportError("artifact path escapes configured storage")
        return path

    def write_pdf(self, hunt_id: str, content: bytes) -> tuple[str, str]:
        relative = f"reports/{_safe_filename(hunt_id, suffix='.pdf')}"
        target = self._path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(content).hexdigest()
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ReportRenderError("could not persist finalized PDF") from exc
        return relative, digest

    def read(self, relative: str) -> bytes:
        path = self._path(relative)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ReportNotFound("finalized PDF is unavailable") from exc


class SqlReportRepository:
    """Engine-backed repository for the report table.

    The SQL predicates intentionally include ``owner_id`` on every read/write,
    so a guessed hunt or report UUID cannot cross an ownership boundary.
    """

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    @staticmethod
    def _decode(row: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(row)
        for key in ("agent_draft", "draft_content", "final_content", "query_appendix", "finding_ids", "evidence_ids", "query_ids"):
            value = result.get(key)
            if isinstance(value, str):
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return result

    def get_report(self, *, hunt_id: str, owner_id: str) -> Mapping[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT * FROM reports WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
        return None if row is None else self._decode(row)

    def update_draft(self, *, hunt_id: str, owner_id: str, expected_version: int, content: dict[str, Any]) -> Mapping[str, Any] | None:
        with self.engine.begin() as connection:
            result = connection.execute(text("""UPDATE reports SET draft_content=:content, version=version+1, updated_at_utc=:now
                WHERE hunt_id=:hunt_id AND owner_id=:owner_id AND state='report_draft' AND version=:version"""), {"content": content, "hunt_id": hunt_id, "owner_id": owner_id, "version": expected_version, "now": _now()})
            if result.rowcount != 1:
                return None
            row = connection.execute(text("SELECT * FROM reports WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
        return None if row is None else self._decode(row)

    def finalize(self, *, hunt_id: str, owner_id: str, expected_version: int, content: dict[str, Any], pdf_path: str, pdf_sha256: str, finalized_at_utc: datetime) -> Mapping[str, Any] | None:
        with self.engine.begin() as connection:
            result = connection.execute(text("""UPDATE reports SET state='finalized', final_content=:content, draft_content=:content,
                pdf_path=:pdf_path, pdf_sha256=:pdf_sha256, finalized_by_user_id=:owner_id,
                finalized_at_utc=:finalized_at, updated_at_utc=:finalized_at, version=version+1
                WHERE hunt_id=:hunt_id AND owner_id=:owner_id AND state='report_draft' AND version=:version"""), {"content": content, "pdf_path": pdf_path, "pdf_sha256": pdf_sha256, "owner_id": owner_id, "finalized_at": finalized_at_utc, "hunt_id": hunt_id, "version": expected_version})
            if result.rowcount != 1:
                return None
            row = connection.execute(text("SELECT * FROM reports WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
        return None if row is None else self._decode(row)


class ReportService:
    """Owner-scoped report workflow with optimistic concurrency."""

    def __init__(self, repository: ReportRepository, *, artifact_store: FileArtifactStore, renderer: SecureWeasyPrintRenderer | None = None, display_timezone: str = "UTC", clock: Any = _now) -> None:
        try:
            ZoneInfo(display_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("display_timezone must be a valid IANA timezone") from exc
        self.repository = repository
        self.artifact_store = artifact_store
        self.renderer = renderer or SecureWeasyPrintRenderer()
        self.display_timezone = display_timezone
        self.clock = clock

    def _record(self, hunt_id: str, owner_id: str) -> Mapping[str, Any]:
        record = self.repository.get_report(hunt_id=hunt_id, owner_id=owner_id)
        if record is None:
            raise ReportNotFound("report not found")
        if str(_value(record, "owner_id", owner_id)) != str(owner_id):
            raise ReportForbidden("report is not owned by this user")
        return record

    def _validated(self, content: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
        available = getattr(self.repository, "citation_ids", None)
        kwargs: dict[str, Any] = {}
        if callable(available):
            ids = available(hunt_id=str(record["hunt_id"]), owner_id=str(record["owner_id"]))
            kwargs = {f"available_{key}_ids": set(str(item) for item in ids.get(key, ())) for key in ("finding", "evidence", "query")}
        normalized = validate_report_content(content, **kwargs)
        validator = getattr(self.repository, "validate_citations", None)
        if callable(validator):
            try:
                validator(hunt_id=str(record["hunt_id"]), owner_id=str(record["owner_id"]), content=normalized)
            except ReportError:
                raise
            except Exception as exc:
                raise ReportValidationError("one or more report citations are unavailable") from exc
        return normalized

    def preview(self, *, hunt_id: str, owner_id: str) -> ReportPreview:
        record = self._record(hunt_id, owner_id)
        content = dict(_value(record, "final_content") or _value(record, "draft_content") or _value(record, "agent_draft") or {})
        # A finalized report can still be previewed, but never edited.
        return ReportPreview(str(hunt_id), str(_value(record, "report_id", hunt_id)), int(_value(record, "version", 1)), str(_value(record, "state", "report_draft")), content, render_report_html(content, display_timezone=self.display_timezone))

    def save_draft(self, *, hunt_id: str, owner_id: str, content: Mapping[str, Any], expected_version: int) -> ReportPreview:
        record = self._record(hunt_id, owner_id)
        if str(_value(record, "state")) != "report_draft":
            raise ReportLocked("finalized reports are immutable")
        if int(_value(record, "version", 1)) != expected_version:
            raise ReportConflict("report version is stale; reload before saving")
        normalized = self._validated(content, record)
        saved = self.repository.update_draft(hunt_id=hunt_id, owner_id=owner_id, expected_version=expected_version, content=normalized)
        if saved is None:
            raise ReportConflict("report changed while it was being saved")
        return self.preview(hunt_id=hunt_id, owner_id=owner_id)

    def finalize(self, *, hunt_id: str, owner_id: str, expected_version: int) -> FinalizedReport:
        record = self._record(hunt_id, owner_id)
        state = str(_value(record, "state", "report_draft"))
        if state == "finalized":
            return FinalizedReport(hunt_id, str(_value(record, "report_id", hunt_id)), int(_value(record, "version", expected_version)), state, str(_value(record, "pdf_sha256")), str(_value(record, "pdf_path")), _utc(_value(record, "finalized_at_utc")))
        if state != "report_draft":
            raise ReportLocked("only report_draft reports may be finalized")
        if int(_value(record, "version", 1)) != expected_version:
            raise ReportConflict("report version is stale; reload before finalizing")
        content = self._validated(dict(_value(record, "draft_content") or _value(record, "agent_draft") or {}), record)
        document = render_report_html(content, display_timezone=self.display_timezone)
        pdf = self.renderer.render(document)
        relative_path, digest = self.artifact_store.write_pdf(hunt_id, pdf)
        finalized_at = _utc(self.clock())
        try:
            saved = self.repository.finalize(hunt_id=hunt_id, owner_id=owner_id, expected_version=expected_version, content=content, pdf_path=relative_path, pdf_sha256=digest, finalized_at_utc=finalized_at)
        except Exception:
            # The database remains the source of truth.  An orphan is safe to
            # retry/delete; never expose it as a finalized report.
            try:
                (self.artifact_store.root / relative_path).unlink(missing_ok=True)
            except OSError:
                pass
            raise
        if saved is None:
            try:
                (self.artifact_store.root / relative_path).unlink(missing_ok=True)
            except OSError:
                pass
            raise ReportConflict("report changed while it was being finalized")
        return FinalizedReport(hunt_id, str(_value(saved, "report_id", hunt_id)), int(_value(saved, "version", expected_version + 1)), "finalized", digest, relative_path, finalized_at)

    def download_pdf(self, *, hunt_id: str, owner_id: str) -> DownloadedArtifact:
        record = self._record(hunt_id, owner_id)
        if str(_value(record, "state")) != "finalized" or not _value(record, "pdf_path"):
            raise ReportNotFound("finalized PDF is unavailable")
        content = self.artifact_store.read(str(record["pdf_path"]))
        expected = str(_value(record, "pdf_sha256", ""))
        if expected and hashlib.sha256(content).hexdigest() != expected:
            raise ReportError("stored PDF failed integrity verification")
        return DownloadedArtifact(content, "application/pdf", _safe_filename(str(hunt_id), suffix=".pdf"))


__all__ = [
    "DownloadedArtifact", "FileArtifactStore", "FinalizedReport", "ReportConflict", "ReportError", "ReportForbidden", "ReportLocked", "ReportNotFound", "ReportPreview", "ReportRenderError", "ReportRepository", "ReportService", "ReportValidationError", "SecureWeasyPrintRenderer", "SqlReportRepository", "REQUIRED_SECTIONS", "render_report_html", "validate_report_content",
]


REPORT_LIST_LIMITS = {
    "selected_evidence": 20,
    "entities": 20,
    "timeline": 20,
    "query_appendix": 12,
}

# Default draft detail selection only. Analysts may include more findings;
# this never restricts stored findings or the answer to any approved question.
REPORT_FINDING_DETAIL_TARGET = 10


REPORT_EVIDENCE_FIELDS = {"evidence_id", "query_id", "index", "sourcetype", "event_time_utc"}


REPORT_QUERY_FIELDS = {"query_id", "purpose", "spl", "status", "result_count", "truncated"}


def _validate_report_content(content: Mapping[str, Any], results: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate bounded report structure and retained-evidence references."""

    normalized = json.loads(json.dumps(content, ensure_ascii=False, default=str))
    required = {"hypothesis", "objective_and_scope", "data_sources_used", "findings", "selected_evidence", "entities", "timeline", "coverage_and_limitations", "conclusion_and_disposition", "query_appendix"}
    if not isinstance(normalized, dict) or required.difference(normalized):
        raise Validation("report is missing required sections")
    if len(json.dumps(normalized, ensure_ascii=False).encode("utf-8")) > 1024 * 1024:
        raise Validation("report content exceeds the 1 MiB limit")
    for key in ("hypothesis", "objective_and_scope", "conclusion_and_disposition"):
        if not isinstance(normalized.get(key), str) or not normalized[key].strip():
            raise Validation(f"report section {key!r} must contain text")
    for key in ("data_sources_used", "findings", "selected_evidence", "entities", "timeline", "coverage_and_limitations", "query_appendix"):
        if not isinstance(normalized.get(key), list):
            raise Validation(f"report section {key!r} must be an array")
    for key, limit in REPORT_LIST_LIMITS.items():
        if len(normalized[key]) > limit:
            raise Validation(f"report section {key!r} exceeds the {limit}-item limit")
    if "question_answers" in (results or {}) or "question_answers" in normalized:
        answers = normalized.get("question_answers")
        if not isinstance(answers, list):
            raise Validation("report question_answers must contain every approved question")
        expected = {item["question_id"]: item for item in (results or {}).get("question_answers", [])}
        answered: set[str] = set()
        finding_ids = {str(item.get("finding_id")) for item in (results or {}).get("findings", normalized["findings"]) if isinstance(item, Mapping)}
        for answer in answers:
            if not isinstance(answer, dict) or set(answer) - {"lead_coverage"} != {"question_id", "question", "summary", "finding_ids", "limitations"}:
                raise Validation("report question answer has invalid fields")
            question_id = answer["question_id"]
            if (not isinstance(question_id, str) or not question_id.strip() or question_id in answered
                    or not isinstance(answer["question"], str) or not answer["question"].strip()
                    or (expected and (question_id not in expected or expected[question_id]["question"] != answer["question"]))):
                raise Validation("report question answer does not match an approved question")
            if (not isinstance(answer["finding_ids"], list) or not all(isinstance(value, str) and value in finding_ids for value in answer["finding_ids"])
                    or not isinstance(answer["summary"], str) or not answer["summary"].strip()
                    or not isinstance(answer["limitations"], list) or not all(isinstance(value, str) and value.strip() for value in answer["limitations"])
                    or not (answer["finding_ids"] or answer["limitations"])):
                raise Validation("each report question requires finding references or an explicit limitation")
            if len(answer["finding_ids"]) != len(set(answer["finding_ids"])) or (
                expected and set(answer["finding_ids"]) != set(expected[question_id]["finding_ids"])
            ):
                raise Validation("report question finding references must match the retained question answer")
            if "lead_coverage" in answer or "lead_coverage" in expected.get(question_id, {}):
                if not expected or answer.get("lead_coverage") != expected[question_id].get("lead_coverage"):
                    raise Validation("report lead coverage must match the retained question answer")
            answered.add(question_id)
        if expected and answered != set(expected):
            raise Validation("report question_answers must contain every approved question")
    available_evidence = {str(item.get("evidence_id")) for item in (results or {}).get("evidence", [])}
    if any(not isinstance(item, dict) or set(item).difference(REPORT_EVIDENCE_FIELDS) for item in normalized["selected_evidence"]):
        raise Validation("selected evidence must contain citations only, not raw events")
    cited_evidence = {str(item.get("evidence_id")) for item in normalized["selected_evidence"]}
    if not cited_evidence.issubset(available_evidence):
        raise Validation("report references unavailable evidence")
    if any(not isinstance(item, dict) or set(item).difference(REPORT_QUERY_FIELDS) for item in normalized["query_appendix"]):
        raise Validation("query appendix must contain query summaries only")
    return normalized


def _concise_report_content(
    *,
    hypothesis: str,
    objective: str,
    data_sources: list[str],
    results: Mapping[str, Any],
    coverage_and_limitations: list[str],
    conclusion_and_disposition: str,
) -> dict[str, Any]:
    """Build the bounded report contract without copying raw events."""

    def records(key: str, limit: int) -> list[dict[str, Any]]:
        value = results.get(key, [])
        return [dict(item) for item in value[:limit] if isinstance(item, Mapping)] if isinstance(value, list) else []

    all_evidence = records("evidence", len(results.get("evidence", [])))
    all_findings = records("findings", len(results.get("findings", [])))
    by_id = {str(item.get("finding_id")): item for item in all_findings}
    question_answers = deepcopy(records("question_answers", len(results.get("question_answers", []))))
    # Select detailed findings across approved questions. All findings remain
    # retained; each question also receives a concise summary independently of
    # whether its detailed findings fit the report's presentation allowance.
    selected_ids: list[str] = []
    groups = [sorted(
        item.get("finding_ids", []),
        key=lambda identifier: by_id.get(identifier, {}).get("classification") != "hunt_lead",
    ) for item in question_answers]
    for position in range(max((len(group) for group in groups), default=0)):
        for group in groups:
            if position < len(group) and group[position] in by_id and group[position] not in selected_ids:
                selected_ids.append(group[position])
        if len(selected_ids) >= REPORT_FINDING_DETAIL_TARGET:
            break
    findings = (
        [by_id[identifier] for identifier in selected_ids[:REPORT_FINDING_DETAIL_TARGET]]
        if question_answers else all_findings[:REPORT_FINDING_DETAIL_TARGET]
    )
    for finding in findings:
        for key in ("evidence_ids", "query_ids"):
            if key in finding:
                finding[key] = list(dict.fromkeys(finding[key]))
    cited_ids = {
        str(evidence_id)
        for finding in findings
        for evidence_id in finding.get("evidence_ids", [])
    }
    primary_evidence = [
        item for item in all_evidence
        if item.get("evidence_kind", "raw_event") == "raw_event" and item.get("event_time_utc") != "unknown"
    ]
    evidence_records = sorted(
        primary_evidence,
        key=lambda item: (str(item.get("evidence_id")) not in cited_ids, str(item.get("event_time_utc"))),
    )[:REPORT_LIST_LIMITS["selected_evidence"]]
    evidence = [
        {key: item[key] for key in REPORT_EVIDENCE_FIELDS if key in item}
        for item in evidence_records
    ]
    queries = [
        {key: item[key] for key in REPORT_QUERY_FIELDS - {"spl"} if key in item}
        for item in records("queries", REPORT_LIST_LIMITS["query_appendix"])
    ]
    entities: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    for item in evidence_records:
        event = item.get("selected_result")
        if not isinstance(event, Mapping):
            continue
        for field, entity_type in (("host", "host"), ("user", "user"), ("src_ip", "ip")):
            value = event.get(field)
            values = value if isinstance(value, list) else [value]
            target_values = [item for item in values if not _is_loopback_endpoint(item)]
            for entity in values:
                if isinstance(entity, str) and entity and (not target_values or entity in target_values) and len(entities) < REPORT_LIST_LIMITS["entities"]:
                    candidate = {"entity_type": entity_type, "value": entity}
                    if candidate not in entities:
                        entities.append(candidate)
        timeline_event = {
            "event_time_utc": item.get("event_time_utc", "unknown"),
            "evidence_id": item.get("evidence_id"),
            **{key: event[key] for key in ("host", "user", "src_ip", "action", "result", "process", "parent_process", "file_name", "file_hash", "file_hash_type") if key in event},
        }
        host = timeline_event.get("host")
        host_values = host if isinstance(host, list) else [host]
        target_hosts = [value for value in host_values if value and not _is_loopback_endpoint(value)]
        if target_hosts:
            timeline_event["host"] = target_hosts[0] if len(target_hosts) == 1 else target_hosts
        timeline.append(timeline_event)
    derived_limitations = _derive_report_limitations(results)
    coverage = list(dict.fromkeys([*coverage_and_limitations, *derived_limitations]))
    if len(all_findings) > len(findings):
        coverage.append(f"All {len(all_findings)} retained findings remain available in the hunt results, independently of this report's detail selection.")
    if derived_limitations and "full blast radius is not established" not in conclusion_and_disposition.casefold():
        conclusion_and_disposition = (
            f"{conclusion_and_disposition.rstrip()} "
            "Investigation coverage is limited; the full blast radius is not established."
        )
    return {
        "hypothesis": hypothesis,
        "objective_and_scope": objective,
        "data_sources_used": data_sources,
        "findings": findings,
        "selected_evidence": evidence,
        "entities": entities or records("entities", REPORT_LIST_LIMITS["entities"]),
        "timeline": timeline or records("timeline", REPORT_LIST_LIMITS["timeline"]),
        "coverage_and_limitations": coverage,
        "conclusion_and_disposition": conclusion_and_disposition,
        "query_appendix": queries,
        **({"question_answers": question_answers}
           if "question_answers" in results else {}),
    }


def _is_loopback_endpoint(value: Any) -> bool:
    """Identify a loopback collector address when an event also names a target host."""

    if not isinstance(value, str):
        return False
    host = value.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def _derive_report_limitations(results: Mapping[str, Any]) -> list[str]:
    """Summarize incomplete coverage without copying execution diagnostics."""

    if not any(key in results for key in {"queries", "query_assessments", "follow_up_questions", "adaptive_status", "question_answers"}):
        return []
    evidence_rows = [item for item in results.get("evidence", []) if isinstance(item, Mapping)]
    limitations: list[str] = [evidence_time_bounds(evidence_rows)["limitation"]] if evidence_rows else []

    def add(value: Any) -> None:
        value = " ".join(str(value).split()).strip()
        if value and value not in limitations:
            limitations.append(value)

    if any(item.get("limitations") for item in results.get("question_answers", [])):
        add("Question-specific limitations remain; see the approved question answers.")

    for coverage in query_source_coverage(results):
        missing = [f"{source['index']} ({source['sourcetype']})" for source in coverage["sources"] if source["needs_source_check"]]
        if missing:
            add(f"Query {coverage['query_id']} has no identified retained rows from {', '.join(missing)} "
                "in its truncated result and no completed source-specific check. This is unresolved coverage, not evidence of absence.")
        if coverage["unidentified_retained_count"]:
            add(f"Query {coverage['query_id']} retained {coverage['unidentified_retained_count']} row(s) "
                "whose source pair cannot be established from the result projection and search scope.")

    queries = [item for item in results.get("queries", []) if isinstance(item, Mapping)]
    completed = [item for item in queries if item.get("status") == "completed"]
    if queries and not completed:
        add("No completed searches are available; the report has no completed telemetry coverage.")
    if any(item.get("status") != "completed" for item in queries):
        add("One or more approved searches did not complete; those telemetry results are outside report coverage.")

    assessments = [item for item in results.get("query_assessments", []) if isinstance(item, Mapping)]
    assessed_ids = {
        str(item.get("query_id")) for item in assessments if item.get("query_id")
    }
    assessed_ids.update(
        str(item) for item in results.get("assessed_query_ids", []) if item
    )
    completed_ids = {str(item.get("query_id")) for item in completed if item.get("query_id")}
    if completed_ids and ("query_assessments" in results or "assessed_query_ids" in results):
        if completed_ids.difference(assessed_ids):
            add("One or more completed searches were not assessed; related findings and pivots may be incomplete.")
    for item in assessments if "question_answers" not in results else []:
        if item.get("answered_question") is False:
            question_id = item.get("question_id", "unknown")
            add(f"Approved hunt question {question_id} remains unanswered.")

    follow_ups = [item for item in results.get("follow_up_questions", []) if isinstance(item, Mapping)]
    follow_up_ids = {str(item.get("question_id")) for item in follow_ups if item.get("question_id")}
    completed_question_ids = {str(item.get("question_id")) for item in completed if item.get("question_id")}
    if follow_up_ids.difference(completed_question_ids):
        add("One or more adaptive follow-up questions were not executed; blast-radius coverage may be incomplete.")
    pending_ids = results.get("pending_question_ids", [])
    if pending_ids:
        add("Investigation questions still pending at stop: " + ", ".join(str(value) for value in pending_ids) + ".")
    for decision in results.get("follow_up_decisions", []) if "question_answers" not in results else []:
        if isinstance(decision, Mapping) and decision.get("skip_reason"):
            add(f"Question {decision.get('question_id')}: {decision['skip_reason']}")

    evidence = results.get("evidence", [])
    evidence_truncated = any(
        isinstance(item, Mapping) and isinstance(item.get("truncation"), Mapping)
        and bool(item["truncation"].get("truncated")) for item in evidence
    ) if isinstance(evidence, list) else False
    if any(bool(item.get("truncated")) for item in queries) or evidence_truncated:
        reasons = {
            "query_row_limit": "per-query row limit", "hunt_row_limit": "per-hunt row limit",
            "query_byte_limit": "per-query byte limit", "hunt_byte_limit": "per-hunt byte limit",
            "query_timeout": "query time limit", "incomplete_page": "incomplete result page",
        }
        stops = sorted({reasons[item["retrieval_stop_reason"]] for item in queries if item.get("retrieval_stop_reason") in reasons})
        add("One or more search results were truncated; conclusions cover retained results only."
            + (" Retrieval stopped at: " + ", ".join(stops) + "." if stops else ""))

    status = str(results.get("adaptive_status", ""))
    if status == "time_reserved_for_synthesis":
        add("Investigation stopped at its time cutoff to reserve time for the report; remaining questions were not assessed.")
    elif status == "budget_reserved_for_synthesis":
        add("Adaptive investigation stopped at the configured budget; remaining questions were not assessed.")
    elif status == "no_follow_up_query":
        add("No validated adaptive follow-up query was executed; blast-radius coverage is limited to completed searches.")

    if any(item.get("status") == "timed_out" for item in results.get("query_ledger", [])):
        add("One or more searches timed out; their missing results do not establish absence of activity.")
    if any(item.get("status") == "skipped_time_cutoff" for item in results.get("query_ledger", [])):
        add("Planned searches were not started because the investigation time cutoff was reached.")
    if any(item.get("status") == "skipped_budget" for item in results.get("query_ledger", [])):
        add("Planned searches were not started because a search or result-storage budget was exhausted; missing results do not establish absence of activity.")

    for item in assessments if "question_answers" not in results else []:
        for value in item.get("limitations", [])[:2] if isinstance(item.get("limitations"), list) else []:
            if value:
                add(f"Assessment limitation: {value}")
    return limitations[:8]


def _question_answer_text(answer: Mapping[str, Any]) -> list[str]:
    """Readable answer text without serializing the full reference collection."""

    return [
        f"Question {answer['question_id']}: {answer['question']}",
        f"Answer: {answer['summary']}",
        f"{len(answer['finding_ids'])} finding(s) retained; full details are available in this hunt's results.",
        *(f"Limitation: {item}" for item in answer["limitations"]),
        *("Advisory lead (observed identity fields): "
          + ("; ".join(f"{key.replace('_', ' ')}: {value}" for key, value in lead["identity_fields"].items()) or "Identity fields unavailable")
          + f". {len(lead['finding_ids'])} finding(s) linked."
          + (f" Unanswered or limited: {lead['limitation']}" if lead["limitation"] else " Analysis still requires review.")
          for lead in answer.get("lead_coverage", [])),
    ]


def _formatted_pdf(title: str, content: Mapping[str, Any]) -> bytes:
    """Render the bounded report contract as a readable, paginated PDF."""

    def text(value: Any) -> list[str]:
        return textwrap.wrap(str(value), width=88, break_long_words=True) or ["None recorded."]

    def section(heading: str, values: Any) -> list[str]:
        lines = text(heading.upper())
        if isinstance(values, list):
            if not values:
                return [*lines, "- None recorded.", ""]
            for value in values:
                if isinstance(value, Mapping):
                    value = "; ".join(f"{key}: {item}" for key, item in value.items())
                wrapped = text(value)
                lines.extend([f"- {wrapped[0]}", *[f"  {item}" for item in wrapped[1:]]])
        else:
            lines.extend(text(values))
        return [*lines, ""]

    lines = ["THREAT HUNTING REPORT", *text(title), ""]
    for heading, key in (
        ("Hunt hypothesis", "hypothesis"),
        ("Objective and scope", "objective_and_scope"),
        ("Data sources used", "data_sources_used"),
        ("Approved question answers", "question_answers"),
        ("Findings", "findings"),
        ("Selected evidence citations", "selected_evidence"),
        ("Entities", "entities"),
        ("Timeline", "timeline"),
        ("Coverage and limitations", "coverage_and_limitations"),
        ("Conclusion and disposition", "conclusion_and_disposition"),
        ("Query appendix", "query_appendix"),
    ):
        if key == "question_answers":
            for answer in content.get(key, []):
                lines.extend(section("Approved question answer", _question_answer_text(answer)))
        elif key == "findings":
            lines.append("SELECTED FINDING DETAILS")
            for finding in content.get(key, []):
                detail = dict(finding)
                for reference_key in ("evidence_ids", "query_ids"):
                    references = list(dict.fromkeys(detail.get(reference_key, [])))
                    detail[reference_key] = ", ".join(str(value) for value in references[:3]) or "None"
                    if len(references) > 3:
                        detail[reference_key] += f"; {len(references)} total references in the hunt results"
                lines.extend(section(str(detail.pop("title", "Finding")), [detail]))
            if not content.get(key):
                lines.extend(["None recorded.", ""])
        else:
            lines.extend(section(heading, content.get(key, [])))

    pages = [lines[index:index + 50] for index in range(0, len(lines), 50)] or [["THREAT HUNTING REPORT"]]

    def escape(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        return "".join(character if 32 <= ord(character) <= 126 else "?" for character in escaped)

    streams = []
    for page in pages:
        commands = ["BT /F1 10 Tf 50 750 Td"]
        for index, line in enumerate(page):
            if index:
                commands.append("0 -14 Td")
            commands.append(f"({escape(line)}) Tj")
        commands.append("ET")
        streams.append("\n".join(commands).encode("ascii"))

    font_number = 3 + len(pages) * 2
    page_numbers = [3 + index * 2 for index in range(len(pages))]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_numbers)}] /Count {len(pages)} >>".encode(),
    ]
    for page_number, stream in zip(page_numbers, streams, strict=True):
        objects.extend([
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_number} 0 R >> >> /Contents {page_number + 1} 0 R >>".encode(),
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        ])
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    output.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def _execution_report_content(row: Mapping[str, Any], plan: HuntPlan, results: Mapping[str, Any]) -> dict[str, Any]:
    evidence_count = len(results.get("evidence", [])) if isinstance(results.get("evidence"), list) else 0
    completed_queries = [
        item for item in results.get("queries", [])
        if isinstance(item, Mapping) and item.get("status") == "completed"
    ] if isinstance(results.get("queries"), list) else []
    findings = results.get("findings", [])
    cited_ids = {str(value) for finding in findings for value in finding.get("evidence_ids", [])}
    classifications = Counter(str(finding.get("classification", "unknown")) for finding in findings)
    classification_counts = ", ".join(f"{count} {name}" for name, count in sorted(classifications.items()))
    conclusion = (
        f"{len(findings)} finding(s) ({classification_counts}) cite {len(cited_ids)} distinct record(s); "
        f"{evidence_count} record(s) were retained across {len(completed_queries)} completed search(es). "
        "The observed telemetry does not by itself establish incident scope, impact, or attribution."
        if results.get("findings")
        else f"No supported findings were identified across {len(completed_queries)} completed search(es) and {evidence_count} retained record(s)."
    )
    completed_ids = {str(query.get("query_id")) for query in completed_queries}
    query_scopes: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    time_limitations: list[str] = []
    for entry in results.get("query_ledger", []):
        if str(entry.get("query_id")) not in completed_ids:
            continue
        proposal = entry.get("proposal", {})
        if proposal.get("earliest_utc") and proposal.get("latest_utc"):
            start = _utc(datetime.fromisoformat(str(proposal["earliest_utc"]).replace("Z", "+00:00")))
            end = _utc(datetime.fromisoformat(str(proposal["latest_utc"]).replace("Z", "+00:00")))
            if start > plan.scope.earliest_utc or end < plan.scope.latest_utc:
                time_limitations.append(
                    f"Query {entry['query_id']} searched only {proposal['earliest_utc']} to {proposal['latest_utc']}. "
                    "Any absence inferred from this search is limited to its filters and this subset of the approved time range."
                )
        indexes = tuple(sorted({str(value) for value in proposal.get("indexes", [])}))
        sourcetypes = tuple(sorted({str(value) for value in proposal.get("sourcetypes", [])}))
        if indexes and sourcetypes:
            query_scopes[str(entry["query_id"])] = (indexes, sourcetypes)
    searched_scopes = set(query_scopes.values())
    # Older results may lack a ledger. Records establish only observed sources.
    for evidence in results.get("evidence", []):
        query_id = str(evidence.get("query_id"))
        if query_id in completed_ids and query_id not in query_scopes and evidence.get("index") and evidence.get("sourcetype"):
            searched_scopes.add(((str(evidence["index"]),), (str(evidence["sourcetype"]),)))
    missing_sources = [
        f"Planned source not searched: {source.index} ({sourcetype})."
        for source in plan.data_sources for sourcetype in source.sourcetypes
        if not any(source.index in indexes and sourcetype in kinds for indexes, kinds in searched_scopes)
    ]
    completed_questions = {str(query.get("question_id")) for query in completed_queries}
    missing_questions = [
        f"Approved hunt question {question.question_id} was not executed: {question.question}"
        for question in plan.questions if question.question_id not in completed_questions
    ]
    return _concise_report_content(
        hypothesis=row["hypothesis"],
        objective=row["objective"],
        data_sources=[
            f"{', '.join(indexes)} ({'query sourcetypes: ' if len(indexes) > 1 else ''}{', '.join(kinds)})"
            for indexes, kinds in sorted(searched_scopes)
        ],
        results=results,
        coverage_and_limitations=[*plan.coverage_limitations, *missing_questions, *missing_sources, *time_limitations],
        conclusion_and_disposition=conclusion,
    )
