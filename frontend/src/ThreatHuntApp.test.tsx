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
});
