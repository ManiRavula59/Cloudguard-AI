"""Unit tests for Task 3: Multimodal Screenshot Audit (vision_extractor.py).

Verifies:
1. Decoding and validation of screenshot images (Pillow).
2. Strict schema extraction and accurate tracking of extracted vs null fields.
3. FastAPI endpoint POST /audit-from-screenshot.
4. Seamless reuse of the LangChain audit pipeline without code duplication.
"""

import io
import json
from unittest.mock import MagicMock, patch
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.models import AuditScorecard, ResourceConfig
from app.vision_extractor import _clean_json_text, extract_config_from_image


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_image_bytes() -> bytes:
    """Generates a small valid PNG image in-memory for testing."""
    image = Image.new("RGB", (100, 100), color=(73, 109, 137))
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def test_clean_json_text():
    """Verifies that markdown code fence wrappers are cleanly removed."""
    raw_markdown = "```json\n{\"resource_name\": \"bucket-1\"}\n```"
    cleaned = _clean_json_text(raw_markdown)
    assert cleaned == '{"resource_name": "bucket-1"}'

    plain = '{"resource_name": "bucket-2"}'
    assert _clean_json_text(plain) == plain


def test_extract_config_invalid_image():
    """Verifies that corrupted or non-image bytes raise ValueError."""
    with pytest.raises(ValueError, match="Invalid image file"):
        extract_config_from_image(b"not-an-image-file")


def test_extract_config_missing_api_key(sample_image_bytes: bytes):
    """Verifies honest RuntimeError when Gemini API key is missing."""
    with patch("app.vision_extractor.settings.gemini_api_key", None):
        with pytest.raises(RuntimeError, match="Gemini API key is not configured"):
            extract_config_from_image(sample_image_bytes, api_key=None)


def test_extract_config_extracted_vs_null_fields(sample_image_bytes: bytes):
    """Verifies that extracted vs null fields are strictly categorized."""
    # Simulate Gemini Vision returning only partially visible attributes
    mock_gemini_json = json.dumps(
        {
            "resource_type": "storage.googleapis.com/Bucket",
            "resource_name": "finance-vault-gcs",
            "public_access_prevention": "enforced",
            "uniform_bucket_level_access": True,
            "encryption_type": None,  # Not visible in screenshot
            "versioning_enabled": None,  # Not visible in screenshot
            "logging_enabled": None,  # Not visible in screenshot
        }
    )

    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = f"```json\n{mock_gemini_json}\n```"
    mock_model.generate_content.return_value = mock_response

    config, extracted, nulls = extract_config_from_image(
        image_bytes=sample_image_bytes,
        model_override=mock_model,
    )

    assert config.resource_name == "finance-vault-gcs"
    assert config.public_access_prevention == "enforced"
    assert config.uniform_bucket_level_access is True
    assert config.encryption_type is None

    # Verify extracted fields list
    assert "resource_name" in extracted
    assert "public_access_prevention" in extracted
    assert "uniform_bucket_level_access" in extracted

    # Verify null fields list
    assert "encryption_type" in nulls
    assert "versioning_enabled" in nulls
    assert "logging_enabled" in nulls


def test_endpoint_audit_from_screenshot_success(test_client: TestClient, sample_image_bytes: bytes):
    """Verifies that POST /audit-from-screenshot executes vision extraction and audit pipeline."""
    mock_config = ResourceConfig(
        resource_type="storage.googleapis.com/Bucket",
        resource_name="screenshot-bucket-prod",
        public_access_prevention="unspecified",
        uniform_bucket_level_access=False,
    )
    mock_extracted = ["resource_type", "resource_name", "public_access_prevention", "uniform_bucket_level_access"]
    mock_nulls = ["encryption_type", "versioning_enabled", "logging_enabled"]

    mock_scorecard = AuditScorecard(
        status="FAIL",
        risk_level="CRITICAL",
        summary="Public access detected from screenshot analysis.",
        violations=[],
        citations=["CIS GCP 5.2"],
        remediation_steps=["gcloud storage buckets update gs://bucket --public-access-prevention"],
    )

    with patch(
        "app.main.extract_config_from_image",
        return_value=(mock_config, mock_extracted, mock_nulls),
    ):
        with patch("app.main.run_audit", return_value=mock_scorecard):
            with patch("app.main.log_audit_to_sheet", return_value=False):
                files = {
                    "file": ("console_settings.png", sample_image_bytes, "image/png"),
                }
                data = {
                    "compliance_framework": "CIS Google Cloud Foundations Benchmark v3.0",
                }
                response = test_client.post("/audit-from-screenshot", files=files, data=data)
                assert response.status_code == 200
                res_data = response.json()

                # Verify vision extraction categorization
                assert res_data["extracted_config"]["resource_name"] == "screenshot-bucket-prod"
                assert "public_access_prevention" in res_data["extracted_fields"]
                assert "encryption_type" in res_data["null_fields"]

                # Verify audit result reuses the same pipeline
                audit_result = res_data["audit_result"]
                assert audit_result["resource_name"] == "screenshot-bucket-prod"
                assert audit_result["scorecard"]["status"] == "FAIL"
                assert audit_result["scorecard"]["risk_level"] == "CRITICAL"
                assert audit_result["logged_to_sheet"] is False


def test_endpoint_audit_from_screenshot_empty_file(test_client: TestClient):
    """Verifies that uploading an empty file returns 400 Bad Request."""
    files = {
        "file": ("empty.png", b"", "image/png"),
    }
    response = test_client.post("/audit-from-screenshot", files=files)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
