"""Report drafts, secure PDF rendering, and owner-scoped report access.

The module deliberately keeps persistence behind a small repository protocol.
The SQL implementation uses the ``reports`` table from :mod:`services.schema`,
while tests and the application composition root may provide a transactionally
equivalent repository.  No report text is ever treated as HTML or as a URL.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
        "findings": f"<ul>{list_items(findings)}</ul>",
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
