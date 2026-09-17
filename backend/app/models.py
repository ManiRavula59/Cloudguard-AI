"""Data contracts and Pydantic schemas for CloudGuard AI.

Defines schemas for cloud resource configurations, compliance audit requests,
scorecards, policy violations, grounding citations, and multimodal extraction.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ResourceConfig(BaseModel):
    """Normalized schema representing a Google Cloud resource configuration.

    Designed to capture security-relevant attributes for resources like
    Cloud Storage Buckets, Cloud SQL instances, Compute Engine VMs, and BigQuery datasets.
    """

    resource_type: str = Field(
        default="storage.googleapis.com/Bucket",
        description="GCP Resource Type identifier (e.g. storage.googleapis.com/Bucket, sqladmin.googleapis.com/Instance)",
    )
    resource_name: str = Field(
        ...,
        description="Unique name or resource path of the cloud resource being audited",
        examples=["prod-customer-pii-storage-01"],
    )
    public_access_prevention: Optional[str] = Field(
        default=None,
        description="Public Access Prevention status: 'enforced', 'inherited', or 'unspecified'",
    )
    uniform_bucket_level_access: Optional[bool] = Field(
        default=None,
        description="Whether Uniform Bucket-Level Access (UBLA) is enabled",
    )
    encryption_type: Optional[str] = Field(
        default=None,
        description="Encryption configuration: 'CMEK' (Customer Managed), 'GOOGLE_MANAGED', or 'NONE'",
    )
    versioning_enabled: Optional[bool] = Field(
        default=None,
        description="Whether object versioning is activated for disaster recovery and retention",
    )
    logging_enabled: Optional[bool] = Field(
        default=None,
        description="Whether audit/access logging is active and streaming to Cloud Logging",
    )
    require_ssl: Optional[bool] = Field(
        default=None,
        description="Whether enforced SSL/TLS is enabled (e.g. for Cloud SQL)",
    )
    authorized_networks: Optional[List[str]] = Field(
        default=None,
        description="Allowed IP CIDR blocks or 0.0.0.0/0 exposure checks",
    )
    additional_attributes: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Arbitrary additional cloud configuration key-values",
    )


class PolicyViolation(BaseModel):
    """Identified compliance violation grounded in a compliance rulebook."""

    rule_id: str = Field(
        ...,
        description="Canonical standard rule identifier, e.g. 'CIS-GCP-5.2'",
        examples=["CIS-GCP-5.2"],
    )
    title: str = Field(..., description="Short title describing the violation")
    severity: str = Field(
        ...,
        description="Severity ranking: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'",
        examples=["CRITICAL"],
    )
    description: str = Field(..., description="Detailed explanation of the policy breach")
    citation: Optional[str] = Field(
        default=None,
        description="Source document title, benchmark section, or URL from the RAG datastore",
    )
    remediation: Optional[str] = Field(
        default=None,
        description="Actionable gcloud CLI command or Terraform snippet to fix the violation",
    )


class AuditScorecard(BaseModel):
    """The compliance evaluation scorecard returned by CloudGuard AI."""

    status: str = Field(
        ...,
        description="Overall compliance verdict: 'PASS', 'FAIL', or 'WARNING'",
        examples=["FAIL"],
    )
    risk_level: str = Field(
        ...,
        description="Overall assessed security risk: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'CLEAN'",
        examples=["CRITICAL"],
    )
    summary: str = Field(..., description="Executive summary of the compliance audit findings")
    violations: List[PolicyViolation] = Field(
        default_factory=list,
        description="List of specific rule violations identified by the RAG agent",
    )
    citations: List[str] = Field(
        default_factory=list,
        description="Grounded sources, benchmarks, or documentation citations",
    )
    remediation_steps: List[str] = Field(
        default_factory=list,
        description="Sequenced list of remediation commands or recommendations",
    )


class AuditRequest(BaseModel):
    """Input payload for auditing a cloud resource configuration."""

    resource_config: ResourceConfig
    compliance_framework: str = Field(
        default="CIS Google Cloud Foundations Benchmark v3.0",
        description="The compliance standard to audit against (e.g. CIS GCP Benchmark, HIPAA, PCI-DSS)",
    )


class AuditResponse(BaseModel):
    """Response returned by the /audit endpoint."""

    resource_name: str
    framework: str
    scorecard: AuditScorecard
    logged_to_sheet: bool = Field(
        default=False,
        description="Indicates whether the scorecard was successfully appended to Google Sheets",
    )
    sheet_error: Optional[str] = Field(
        default=None,
        description="Contains error message if Google Workspace logging failed (non-breaking)",
    )
    agent_mode: str = Field(
        default="live",
        description="'live' when evaluated against live Vertex AI Agent Builder, or diagnostic note",
    )
    error: Optional[str] = Field(
        default=None,
        description="System error details if audit failed",
    )


class ScreenshotAuditResponse(BaseModel):
    """Response returned by the multimodal /audit-from-screenshot endpoint."""

    extracted_config: ResourceConfig
    extracted_fields: List[str] = Field(
        default_factory=list,
        description="Resource config fields successfully read and extracted from the screenshot",
    )
    null_fields: List[str] = Field(
        default_factory=list,
        description="Fields not legible in the screenshot and therefore explicitly defaulted to null",
    )
    audit_result: AuditResponse
