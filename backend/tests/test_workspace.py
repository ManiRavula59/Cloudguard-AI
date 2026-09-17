"""Unit tests for Task 2: Google Workspace Sheets Integration (workspace_writer.py).

Verifies:
1. Proper row formatting [timestamp, resource_name, scorecard_text].
2. Validation error when sheet_id is omitted.
3. Execution of Google Sheets API append call.
4. Non-breaking error handling in the /audit endpoint when Sheets API fails or credentials are missing.
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import ResourceConfig, AuditScorecard
from app.workspace_writer import log_audit_to_sheet


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_resource_config() -> ResourceConfig:
    return ResourceConfig(
        resource_type="storage.googleapis.com/Bucket",
        resource_name="finance-records-bucket",
        public_access_prevention="enforced",
        uniform_bucket_level_access=True,
    )


def test_log_audit_to_sheet_missing_sheet_id():
    """Verifies that log_audit_to_sheet raises ValueError when no sheet ID is provided."""
    with patch("app.workspace_writer.settings.google_sheet_id", None):
        with pytest.raises(ValueError, match="Target Google Sheet ID is missing"):
            log_audit_to_sheet(
                resource_name="test-resource",
                scorecard_text="PASS",
                sheet_id=None,
            )


def test_log_audit_to_sheet_success_append():
    """Verifies that log_audit_to_sheet formats the row and executes the Google Sheets append call."""
    mock_service = MagicMock()
    mock_values = MagicMock()
    mock_append = MagicMock()
    mock_append.execute.return_value = {
        "updates": {
            "updatedRows": 1,
            "updatedRange": "Sheet1!A2:C2",
        }
    }
    mock_values.append.return_value = mock_append
    mock_service.spreadsheets.return_value.values.return_value = mock_values

    success = log_audit_to_sheet(
        resource_name="finance-records-bucket",
        scorecard_text="[FAIL | Risk: HIGH] Public access detected | Violations: 1",
        sheet_id="sample-sheet-id-12345",
        service=mock_service,
    )

    assert success is True
    assert mock_values.append.called
    call_kwargs = mock_values.append.call_args[1]
    assert call_kwargs["spreadsheetId"] == "sample-sheet-id-12345"
    assert call_kwargs["range"] == "Sheet1!A:C"
    assert call_kwargs["valueInputOption"] == "USER_ENTERED"

    appended_row = call_kwargs["body"]["values"][0]
    assert len(appended_row) == 3
    # First item is ISO timestamp
    assert "UTC" in appended_row[0]
    # Second item is resource name
    assert appended_row[1] == "finance-records-bucket"
    # Third item is scorecard text
    assert "[FAIL | Risk: HIGH]" in appended_row[2]


def test_audit_endpoint_logged_to_sheet_success(test_client: TestClient, sample_resource_config: ResourceConfig):
    """Verifies that /audit returns logged_to_sheet: True when Workspace write succeeds."""
    mock_scorecard = AuditScorecard(
        status="PASS",
        risk_level="CLEAN",
        summary="Bucket adheres to security baselines.",
        violations=[],
        citations=["CIS Benchmark v3.0"],
        remediation_steps=[],
    )

    with patch("app.main.run_audit", return_value=mock_scorecard):
        with patch("app.main.log_audit_to_sheet", return_value=True) as mock_sheet:
            payload = {
                "resource_config": sample_resource_config.model_dump(),
                "compliance_framework": "CIS Google Cloud Foundations Benchmark v3.0",
            }
            response = test_client.post("/audit", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert data["resource_name"] == "finance-records-bucket"
            assert data["logged_to_sheet"] is True
            assert data["sheet_error"] is None
            assert mock_sheet.called


def test_audit_endpoint_logged_to_sheet_non_blocking_failure(test_client: TestClient, sample_resource_config: ResourceConfig):
    """Verifies that Workspace failure does NOT break the main /audit response (still 200 OK)."""
    mock_scorecard = AuditScorecard(
        status="FAIL",
        risk_level="HIGH",
        summary="Bucket has critical misconfigurations.",
        violations=[],
        citations=[],
        remediation_steps=[],
    )

    with patch("app.main.run_audit", return_value=mock_scorecard):
        # Simulate missing credentials.json or OAuth failure
        with patch("app.main.log_audit_to_sheet", side_effect=FileNotFoundError("credentials.json not found")):
            payload = {
                "resource_config": sample_resource_config.model_dump(),
                "compliance_framework": "CIS Google Cloud Foundations Benchmark v3.0",
            }
            response = test_client.post("/audit", json=payload)
            assert response.status_code == 200  # Must NOT be 500!
            data = response.json()
            assert data["resource_name"] == "finance-records-bucket"
            assert data["scorecard"]["status"] == "FAIL"
            assert data["logged_to_sheet"] is False
            assert "credentials.json not found" in data["sheet_error"]
