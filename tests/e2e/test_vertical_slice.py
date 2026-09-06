"""HTTP verification for the deterministic local threat-hunt vertical slice.

These tests deliberately use the local demo adapters. They verify application
workflow and persistence contracts; they do not validate production Splunk data or
model accuracy.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from threat_hunting.main import create_app
from threat_hunting.services.workflow import IntegrationUnavailable


DEMO_PASSWORD = "test-only-password"


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    return TestClient(create_app(engine, local_demo=True, demo_password=DEMO_PASSWORD))


def _expect(response, status_code: int = 200):
    assert response.status_code == status_code, response.text
    return response.json()


def test_local_demo_exercises_the_approval_gated_vertical_slice() -> None:
    with _client() as client:
        assert client.get("/api/hunts").status_code == 401
        assert client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "wrong"},
        ).status_code == 401

        login = _expect(client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": DEMO_PASSWORD},
        ))
        assert "password" not in str(login).lower()
        headers = {"Authorization": f"Bearer {login['access_token']}"}

        hunt = _expect(client.post(
            "/api/hunts",
            headers=headers,
            json={
                "title": "Suspicious authentication activity",
                "hypothesis": "A compromised account authenticated from an unusual source.",
                "objective": "Identify scoped authentication activity that supports or refutes the hypothesis.",
                "threat_intelligence": "Advisory: prioritize unusual source geography.",
                "synthetic_data": "user=analyst src_ip=192.0.2.17 EventCode=4624",
            },
        ), 201)
        hunt_id = hunt["hunt_id"]
        assert hunt["state"] == "created"
        assert "password" not in str(hunt).lower()
        expected_input_context = {
            "threat_intelligence": "Advisory: prioritize unusual source geography.",
            "synthetic_data": "user=analyst src_ip=192.0.2.17 EventCode=4624",
            "classification": "analyst_supplied_context",
        }

        # Consequential execution fails closed until the exact plan is approved.
        blocked = client.post(f"/api/hunts/{hunt_id}/execute", headers=headers)
        assert blocked.status_code == 409
        assert "approval" in blocked.json()["detail"].lower()

        hunt = _expect(client.post(f"/api/hunts/{hunt_id}/discover", headers=headers))
        assert hunt["state"] == "awaiting_plan_review"
        assert hunt["plan_version"] == 1
        assert hunt["discovery_snapshot"]["mode"] == "deterministic_local_demo"
        assert hunt["discovery_snapshot"]["coverage_limitations"]
        assert hunt["discovery_snapshot"]["input_context"] == expected_input_context
        assert hunt["plan"]["input_context"] == expected_input_context

        stale = client.put(
            f"/api/hunts/{hunt_id}/plan",
            headers=headers,
            json={"expected_version": 99, "plan": hunt["plan"]},
        )
        assert stale.status_code == 409

        hunt = _expect(client.post(
            f"/api/hunts/{hunt_id}/plan/revise",
            headers=headers,
            json={"instruction": "Narrow the scope to the documented security indexes."},
        ))
        assert hunt["plan_version"] == 2
        assert hunt["approval"] is None

        hunt = _expect(client.post(
            f"/api/hunts/{hunt_id}/plan/reject",
            headers=headers,
            json={"analyst_note": "Clarify the success criteria before execution."},
        ))
        assert hunt["state"] == "plan_draft"
        assert hunt["approval"] is None
        assert client.post(f"/api/hunts/{hunt_id}/execute", headers=headers).status_code == 409

        edited_plan = dict(hunt["plan"])
        edited_plan["objective"] = "Review unusual authentication events and retain supporting evidence."
        hunt = _expect(client.put(
            f"/api/hunts/{hunt_id}/plan",
            headers=headers,
            json={"expected_version": hunt["plan_version"], "plan": edited_plan},
        ))
        assert hunt["state"] == "awaiting_plan_review"
        approved_version = hunt["plan_version"]

        hunt = _expect(client.post(
            f"/api/hunts/{hunt_id}/plan/approve",
            headers=headers,
            json={"analyst_note": "Scope and evidence requirements reviewed."},
        ))
        assert hunt["state"] == "approved"
        assert hunt["approval"]["plan_version"] == approved_version
        assert len(hunt["approval"]["plan_sha256"]) == 64

        # Approval locks plan content; it cannot be changed and then executed under
        # the old approval record.
        assert client.put(
            f"/api/hunts/{hunt_id}/plan",
            headers=headers,
            json={"expected_version": approved_version, "plan": edited_plan},
        ).status_code == 409

        hunt = _expect(client.post(f"/api/hunts/{hunt_id}/execute", headers=headers))
        assert hunt["state"] == "report_draft"

        results = _expect(client.get(f"/api/hunts/{hunt_id}/results", headers=headers))
        assert results["mode"] == "deterministic_local_demo"
        assert results["findings"]
        assert results["evidence"]
        assert results["entities"]
        assert results["timeline"]
        assert results["queries"]
        assert results["evidence"][0]["disclaimer"]

        report = _expect(client.get(f"/api/hunts/{hunt_id}/report", headers=headers))
        assert report["state"] == "report_draft"
        invalid_report = client.put(
            f"/api/hunts/{hunt_id}/report",
            headers=headers,
            json={"expected_version": report["version"], "content": {"unsupported_claim": "host compromised"}},
        )
        assert invalid_report.status_code == 422
        edited_report = dict(report["content"])
        edited_report["conclusion_and_disposition"] = (
            "Analyst reviewed the deterministic demo lead; production validation remains required."
        )
        report = _expect(client.put(
            f"/api/hunts/{hunt_id}/report",
            headers=headers,
            json={"expected_version": report["version"], "content": edited_report},
        ))
        assert report["content"]["conclusion_and_disposition"] == edited_report["conclusion_and_disposition"]

        report = _expect(client.post(
            f"/api/hunts/{hunt_id}/report/finalize",
            headers=headers,
            json={"expected_version": report["version"]},
        ))
        assert report["state"] == "finalized"
        assert client.put(
            f"/api/hunts/{hunt_id}/report",
            headers=headers,
            json={"expected_version": report["version"], "content": edited_report},
        ).status_code == 409

        pdf = client.get(f"/api/hunts/{hunt_id}/report/pdf", headers=headers)
        assert pdf.status_code == 200
        assert pdf.headers["content-type"].startswith("application/pdf")
        assert pdf.content.startswith(b"%PDF-")

        # Owner-scoped lookup semantics do not reveal whether another hunt exists.
        assert client.get(
            "/api/hunts/00000000-0000-0000-0000-000000000000",
            headers=headers,
        ).status_code == 404


def test_local_demo_requires_explicit_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREAT_HUNTING_DEMO_PASSWORD", raising=False)
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with pytest.raises(IntegrationUnavailable, match="credentials are not configured"):
        create_app(engine, local_demo=True)


@pytest.mark.parametrize("field", ["threat_intelligence", "synthetic_data"])
def test_hunt_context_inputs_reject_more_than_50000_characters(field: str) -> None:
    with _client() as client:
        login = _expect(client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": DEMO_PASSWORD},
        ))
        response = client.post(
            "/api/hunts",
            headers={"Authorization": f"Bearer {login['access_token']}"},
            json={
                "title": "Bounded input test",
                "hypothesis": "Test boundary validation.",
                "objective": "Reject an oversized analyst input.",
                field: "x" * 50_001,
            },
        )
        assert response.status_code == 422
