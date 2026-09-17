"""Test suite for CloudGuard AI Task 1 (LangChain Orchestration Layer).

Verifies:
1. Backward-compatibility of `build_audit_prompt()` in `main.py`.
2. LangChain PromptTemplate and RunnableLambda orchestration pipeline.
3. Output parsing of agent scorecards and citations.
4. FastAPI `/audit` and `/health` endpoints.
5. Honest error propagation when GCP configurations are missing/invalid.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app, build_audit_prompt
from app.models import ResourceConfig, AuditRequest
from app.langchain_orchestrator import (
    prompt_template,
    format_config_details,
    _parse_scorecard_step,
    run_audit,
)


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_gcs_bucket_config() -> ResourceConfig:
    return ResourceConfig(
        resource_type="storage.googleapis.com/Bucket",
        resource_name="prod-public-user-data",
        public_access_prevention="unspecified",
        uniform_bucket_level_access=False,
        encryption_type="GOOGLE_MANAGED",
        versioning_enabled=False,
        logging_enabled=False,
    )


@pytest.fixture
def sample_compliant_bucket_config() -> ResourceConfig:
    return ResourceConfig(
        resource_type="storage.googleapis.com/Bucket",
        resource_name="secure-archive-vault",
        public_access_prevention="enforced",
        uniform_bucket_level_access=True,
        encryption_type="CMEK",
        versioning_enabled=True,
        logging_enabled=True,
    )


def test_health_endpoint(test_client: TestClient):
    """Verifies that the /health endpoint responds with 200 OK and service metadata."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CloudGuard AI"


def test_build_audit_prompt_backward_compatibility(sample_gcs_bucket_config: ResourceConfig):
    """Verifies that build_audit_prompt() signature remains intact and formats as expected."""
    prompt = build_audit_prompt(
        resource_config=sample_gcs_bucket_config,
        framework="CIS Google Cloud Foundations Benchmark v3.0",
    )
    assert "prod-public-user-data" in prompt
    assert "storage.googleapis.com/Bucket" in prompt
    assert "CIS Google Cloud Foundations Benchmark v3.0" in prompt
    assert "Public Access Prevention: unspecified" in prompt
    assert "Uniform Bucket-Level Access (UBLA): Disabled" in prompt


def test_format_config_details(sample_gcs_bucket_config: ResourceConfig):
    """Verifies format_config_details produces human-readable configuration attributes."""
    details = format_config_details(sample_gcs_bucket_config)
    assert "Public Access Prevention: unspecified" in details
    assert "Uniform Bucket-Level Access (UBLA): Disabled" in details
    assert "Cloud Audit/Access Logging: Disabled" in details


def test_prompt_template_input_variables():
    """Validates that LangChain PromptTemplate specifies the required input_variables."""
    assert set(prompt_template.input_variables) == {
        "compliance_framework",
        "resource_type",
        "resource_name",
        "config_details",
    }


def test_parse_scorecard_step_failure_case():
    """Tests the parsing step on a realistic agent scorecard indicating compliance failure."""
    agent_output = {
        "response_text": (
            "STATUS: FAIL\n"
            "RISK_LEVEL: CRITICAL\n"
            "SUMMARY: The storage bucket is publicly accessible and lacks uniform IAM controls.\n"
            "VIOLATIONS:\n"
            "- [CIS-GCP-5.2] - [CRITICAL]: Bucket is publicly accessible without access prevention (Citation: CIS Google Cloud Benchmark v3.0 Section 5.2) | Remediation: gcloud storage buckets update gs://bucket --public-access-prevention\n"
            "- [CIS-GCP-5.3] - [HIGH]: Uniform Bucket-Level Access is disabled (Citation: CIS GCP 5.3) | Remediation: gcloud storage buckets update gs://bucket --uniform-bucket-level-access\n"
            "REMEDIATIONS:\n"
            "- 1. Enforce public access prevention: gcloud storage buckets update gs://bucket --public-access-prevention\n"
            "- 2. Enable UBLA: gcloud storage buckets update gs://bucket --uniform-bucket-level-access\n"
        ),
        "citations": [
            "CIS Google Cloud Foundations Benchmark v3.0",
            "Google Cloud Storage Security Best Practices",
        ],
    }

    scorecard = _parse_scorecard_step(agent_output)
    assert scorecard.status == "FAIL"
    assert scorecard.risk_level == "CRITICAL"
    assert "publicly accessible" in scorecard.summary
    assert len(scorecard.violations) == 2
    assert scorecard.violations[0].rule_id == "CIS-GCP-5.2"
    assert scorecard.violations[0].severity == "CRITICAL"
    assert scorecard.violations[0].citation == "CIS Google Cloud Benchmark v3.0 Section 5.2"
    assert "gcloud storage buckets update" in scorecard.violations[0].remediation
    assert len(scorecard.citations) == 2
    assert len(scorecard.remediation_steps) == 2


def test_parse_scorecard_step_compliant_case():
    """Tests the parsing step on a compliant scorecard."""
    agent_output = {
        "response_text": (
            "STATUS: PASS\n"
            "RISK_LEVEL: CLEAN\n"
            "SUMMARY: Resource fully complies with CIS Google Cloud Foundations Benchmark.\n"
            "VIOLATIONS:\n"
            "REMEDIATIONS:\n"
            "- Maintain periodic audit posture."
        ),
        "citations": ["CIS GCP Benchmark v3.0"],
    }

    scorecard = _parse_scorecard_step(agent_output)
    assert scorecard.status == "PASS"
    assert scorecard.risk_level == "CLEAN"
    assert len(scorecard.violations) == 0


def test_langchain_orchestrator_run_audit(sample_gcs_bucket_config: ResourceConfig):
    """Tests the entire LangChain pipeline execution using a mocked Vertex AI step."""
    mock_agent_response = {
        "response_text": (
            "STATUS: FAIL\n"
            "RISK_LEVEL: HIGH\n"
            "SUMMARY: Bucket lacks encryption and access enforcement.\n"
            "VIOLATIONS:\n"
            "- [CIS-5.1] - [HIGH]: Public access not restricted | Remediation: gcloud storage update\n"
            "REMEDIATIONS:\n"
            "- Enforce access prevention."
        ),
        "citations": ["CIS GCP 5.1"],
    }

    # Patch the Vertex AI agent step to test the LangChain pipeline mechanics
    with patch("app.langchain_orchestrator.ask_agent", return_value=mock_agent_response) as mock_ask:
        scorecard = run_audit(
            resource_config=sample_gcs_bucket_config,
            framework="CIS Google Cloud Foundations Benchmark v3.0",
        )
        assert mock_ask.called
        assert scorecard.status == "FAIL"
        assert scorecard.risk_level == "HIGH"
        assert len(scorecard.violations) == 1
        assert scorecard.violations[0].rule_id == "CIS-5.1"


def test_api_audit_endpoint_success(test_client: TestClient, sample_gcs_bucket_config: ResourceConfig):
    """Tests the FastAPI /audit endpoint invoking the LangChain orchestrator."""
    mock_agent_response = {
        "response_text": (
            "STATUS: FAIL\n"
            "RISK_LEVEL: CRITICAL\n"
            "SUMMARY: Critical compliance exposure detected.\n"
            "VIOLATIONS:\n"
            "- [CIS-GCP-5.2] - [CRITICAL]: Public access prevention disabled | Remediation: gcloud storage buckets update\n"
            "REMEDIATIONS:\n"
            "- Run gcloud command."
        ),
        "citations": ["CIS Benchmark Section 5.2"],
    }

    with patch("app.langchain_orchestrator.ask_agent", return_value=mock_agent_response):
        payload = {
            "resource_config": sample_gcs_bucket_config.model_dump(),
            "compliance_framework": "CIS Google Cloud Foundations Benchmark v3.0",
        }
        response = test_client.post("/audit", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["resource_name"] == "prod-public-user-data"
        assert data["scorecard"]["status"] == "FAIL"
        assert data["scorecard"]["risk_level"] == "CRITICAL"
        assert len(data["scorecard"]["violations"]) == 1
        assert data["logged_to_sheet"] is False


def test_api_audit_endpoint_honest_error_handling(test_client: TestClient, sample_gcs_bucket_config: ResourceConfig):
    """Verifies that API surfaces honest 500 error when GCP Vertex AI is unconfigured or fails."""
    # When unconfigured, vertex_agent_client.ask_agent raises RuntimeError
    with patch(
        "app.langchain_orchestrator.ask_agent",
        side_effect=RuntimeError("Vertex AI Agent Builder is not configured. Missing environment variables."),
    ):
        payload = {
            "resource_config": sample_gcs_bucket_config.model_dump(),
            "compliance_framework": "CIS Google Cloud Foundations Benchmark v3.0",
        }
        response = test_client.post("/audit", json=payload)
        assert response.status_code == 500
        assert "Vertex AI Agent Builder is not configured" in response.json()["detail"]
