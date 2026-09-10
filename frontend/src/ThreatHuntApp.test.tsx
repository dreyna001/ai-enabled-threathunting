import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ObservedTimeline, QuestionAnswers } from "./ThreatHuntApp";
import { HuntResults } from "./api/hunts";

describe("observed timeline presentation", () => {
  it("shows raw chronology without findings, bounds rendering, and preserves source fields", () => {
    const evidence = Array.from({ length: 51 }, (_, index) => ({ evidence_id: `e-${index}`, query_id: "q-1",
      event_time_utc: "2026-01-06T04:00:00-05:00", selected_result: { action: "image_load", host: ["collector", "target"],
        process: `<script>process-${index}</script>`, session_id: "native-session", process_guid: "native-guid", file_name: "winhttp.dll" } }));
    const timeline = evidence.map((item) => ({ evidence_id: item.evidence_id, query_id: item.query_id,
      event_time_utc: "2026-01-06T09:00:00Z", query_coverage: "incomplete" }));
    const results: HuntResults = { evidence, timeline, findings: [], entities: [] };
    const markup = renderToStaticMarkup(<ObservedTimeline results={results} />);
    expect(markup).toContain("Observed timeline");
    expect(markup).toContain("Showing 1–50 of 51 matching records");
    expect(markup).toContain("native-session");
    expect(markup).toContain("native-guid");
    expect(markup).toContain("winhttp.dll");
    expect(markup).toContain("2026-01-06T04:00:00-05:00");
    expect(markup).toContain("2026-01-06T09:00:00Z");
    expect(markup).toContain("Search retrieval: incomplete");
    expect(markup).toContain('href="#evidence-e-49"');
    expect(markup).not.toContain('href="#evidence-e-50"');
    expect(markup).toContain("Next records");
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("<details open");
    expect(results.evidence).toHaveLength(51);
    expect(results.timeline).toHaveLength(51);
  });

  it("distinguishes unavailable timeline/source records from no retained raw observations", () => {
    const empty: HuntResults = { evidence: [], timeline: [], findings: [], entities: [] };
    expect(renderToStaticMarkup(<ObservedTimeline results={empty} />)).toContain("No raw observations retained.");
    expect(renderToStaticMarkup(<ObservedTimeline results={{ ...empty, evidence: [{ evidence_id: "e1" }] }} />)).toContain("timeline is unavailable");
    const missing = renderToStaticMarkup(<ObservedTimeline results={{ ...empty, timeline: [{ evidence_id: "missing", event_time_utc: "unknown", query_coverage: "unknown" }] }} />);
    expect(missing).toContain("The source record is unavailable.");
    expect(missing).toContain("Search retrieval: unknown");
    expect(missing).not.toContain("Open source record");
  });
});

describe("question answer presentation", () => {
  it("shows application-owned lead activity with before and after records even without findings", () => {
    const evidence = ["before", "lead", "after"].map((id, index) => ({ evidence_id: id,
      event_time_utc: `2026-01-06T${String(index + 8).padStart(2, "0")}:00:00Z`, selected_result: { action: id === "lead" ? "process_start" : "dns_query", host: "<host>", process: "browser" } }));
    const results: HuntResults = { findings: [], evidence, entities: [], timeline: evidence.map((row) => ({
      evidence_id: row.evidence_id, event_time_utc: row.event_time_utc, query_coverage: "incomplete" })),
      question_answers: [{ question_id: "q1", question: "What happened?", summary: "No model interpretation.", finding_ids: [], limitations: ["Unanswered."],
        lead_coverage: [{ lead_evidence_ids: ["lead"], identity_fields: { host: "<host>", process_guid: "native" }, finding_ids: [], limitation: "Unanswered." }] }],
      lead_activity: { leads: [{ lead_evidence_ids: ["lead"], identity_fields: { host: "<host>", process_guid: "native" },
        anchor_event_time_utc: "2026-01-06T09:00:00Z", limitation: null, scopes: [{ scope_id: "session", periods: [
          { relative_to_lead: "before", raw_record_count: 1, first_event_time_utc: "2026-01-06T08:00:00Z", last_event_time_utc: "2026-01-06T08:00:00Z" },
          { relative_to_lead: "after", raw_record_count: 1, first_event_time_utc: "2026-01-06T10:00:00Z", last_event_time_utc: "2026-01-06T10:00:00Z" }] }] }],
        scopes: [{ scope_id: "session", identity_fields: { host: "<host>", user: "user", session_id: "native-session" },
          evidence_ids: evidence.map((row) => row.evidence_id), raw_record_count: 3, fields: [],
          actions: [{ action: "dns_query", raw_record_count: 2, first_observed_utc: "2026-01-06T08:00:00Z", last_observed_utc: "2026-01-06T10:00:00Z" }],
          query_coverage: [{ query_id: "complete-q", retrieval_status: "complete", matching_raw_record_count: 1, earliest_utc: null, latest_utc: null },
            { query_id: "partial-q", retrieval_status: "incomplete", matching_raw_record_count: 2, earliest_utc: null, latest_utc: null }] }] } };
    const markup = renderToStaticMarkup(<QuestionAnswers results={results} />);
    expect(markup).toContain("Observed activity for the retained leads");
    expect(markup).toContain("3 retained raw records match every selected field");
    expect(markup).toContain("before: 1 records");
    expect(markup).toContain("after: 1 records");
    expect(markup).toContain("dns_query: 2 records");
    expect(markup).toContain("Search complete-q: complete");
    expect(markup).toContain("Search partial-q: incomplete");
    expect(markup).toContain("native-session");
    expect(markup).toContain("Review observed activity for this lead");
    expect(markup).toContain('href="#evidence-before"');
    expect(markup).toContain('href="#evidence-after"');
    expect(markup).toContain("<td>Before</td>");
    expect(markup).toContain("<td>After</td>");
    expect(markup).not.toContain("<host>");
  });

  it("keeps every finding accessible behind a collapsed question summary", () => {
    const findings = Array.from({ length: 2000 }, (_, i) => ({ finding_id: `finding-${i}`, statement: `Observation ${i}` }));
    const results: HuntResults = {
      findings, evidence: [], entities: [], timeline: [],
      question_answers: [{ question_id: "q1", question: "What happened?", summary: "Repeated events and a separate lead were observed.",
        finding_ids: findings.map((finding) => finding.finding_id), limitations: ["Impact remains unknown."] }],
    };
    const markup = renderToStaticMarkup(<QuestionAnswers results={results} />);
    expect(markup).toContain("Repeated events and a separate lead");
    expect(markup).toContain("Impact remains unknown");
    expect(markup).toContain("<details><summary>View all 2000 findings");
    expect(markup).toContain("Observation 1999");
    expect(markup.match(/<pre>/g)).toHaveLength(2000);
    expect(markup).not.toContain("<details open");
    expect(results.findings).toHaveLength(2000);
  });

  it("preserves unanswered questions and escapes source text", () => {
    const markup = renderToStaticMarkup(<QuestionAnswers results={{ findings: [], evidence: [], entities: [], timeline: [],
      question_answers: [{ question_id: "q2", question: "<script>alert(1)</script>", summary: "Insufficient telemetry.", finding_ids: [], limitations: ["Source unavailable."] }] }} />);
    expect(markup).toContain("Insufficient telemetry");
    expect(markup).toContain("Source unavailable");
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("<details>");
    expect(renderToStaticMarkup(<QuestionAnswers results={{ findings: [], evidence: [], entities: [], timeline: [] }} />)).toBe("");
  });

  it("shows source identity and unanswered lead gaps without claiming acceptance", () => {
    const markup = renderToStaticMarkup(<QuestionAnswers results={{ findings: [], evidence: [], entities: [], timeline: [],
      question_answers: [{ question_id: "q1", question: "Related activity?", summary: "Analysis is incomplete.", finding_ids: [], limitations: [],
        lead_coverage: [{ lead_evidence_ids: ["e1"], identity_fields: { host: "<script>unsafe</script>", process_guid: "native-process" },
          finding_ids: [], limitation: "Authentication timeline remains unanswered." }] }] }} />);
    expect(markup).toContain("Review 1 advisory leads");
    expect(markup).toContain("native-process");
    expect(markup).toContain("0 findings linked");
    expect(markup).toContain("Authentication timeline remains unanswered");
    expect(markup).toContain("still require analyst review");
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("<details open");
  });

  it("shows computed scoped counts with missing values and source limitations", () => {
    const markup = renderToStaticMarkup(<QuestionAnswers results={{ findings: [], evidence: [], entities: [], timeline: [],
      question_answers: [{ question_id: "q1", question: "How many values?", summary: "Review the measured inventory.", finding_ids: [], limitations: [],
        inventories: [{ scope: { query_ids: ["query-a"], filters: [{ field: "host", value: "<script>unsafe</script>" }], earliest_utc: null, latest_utc: null },
          raw_record_count: 52,
          fields: [{ field: "process_guid", distinct_literal_value_count: 1, distinct_unambiguous_value_count: 1,
            rows_with_missing_or_nonscalar_value: 3, rows_with_multiple_distinct_values: 2 }],
          limitations: ["Selected search retrieval is incomplete."] }] }] }} />);
    expect(markup).toContain("View measured counts");
    expect(markup).toContain("52 retained raw rows");
    expect(markup).toContain('<th scope="row">process guid</th><td>1</td><td>1</td><td>3</td><td>2</td>');
    expect(markup).toContain("Rows missing values");
    expect(markup).toContain("retrieval is incomplete");
    expect(markup).toContain("Do not add counts from overlapping selections");
    expect(markup).not.toContain("<script>");
  });
});
