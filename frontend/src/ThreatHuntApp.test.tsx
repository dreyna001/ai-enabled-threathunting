import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { QuestionAnswers } from "./ThreatHuntApp";
import { HuntResults } from "./api/hunts";

describe("question answer presentation", () => {
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
