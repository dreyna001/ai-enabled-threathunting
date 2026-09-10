from types import SimpleNamespace

from threat_hunting.services.investigation import _assessment_context


def test_assessment_guidance_requires_scope_pivots_and_honest_stopping() -> None:
    plan = SimpleNamespace(
        hypothesis="A suspicious process may have spread.",
        objective="Determine whether related activity exists in scope.",
        questions=[],
        scope=SimpleNamespace(model_dump=lambda **_: {}),
    )

    context = _assessment_context(
        plan,
        {
            "queries": [],
            "evidence": [],
        },
    )
    rules = " ".join(context["assessment_rules"])

    assert "hosts, users, source or destination IPs, processes, domains, and files" in rules
    assert "scope and spread" in rules
    assert "before or after timeline" in rules
    assert "missing telemetry, noisy results, and truncation" in rules
    assert "concise limitations explanation" in rules
    assert "without requiring arbitrary extra queries" in rules
    assert "A filename match does not establish a hash or path match" in rules
    assert "distinguish it from observed execution and a confirmed incident" in rules
