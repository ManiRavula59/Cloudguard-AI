"""LangChain orchestration layer for CloudGuard AI.

Architecture Note for Google Cloud AI Engineer Interview:
    Why use LangChain to orchestrate the Vertex AI Agent Builder call?
    1. Separation of Concerns: Decouples prompt engineering, versioning, and formatting
       from FastAPI routing and GCP SDK clients.
    2. Composable Pipelines: Employs LangChain Expression Language (LCEL) so that
       prompt construction, agent retrieval, and post-processing parsers operate as
       standardized, observable, and testable Runnables.
    3. Multi-Step Extensibility: Makes it trivial to add pre-flight validation,
       guardrail checks, or multi-agent routing without altering endpoint controllers.
"""

import logging
import re
from typing import Any, Dict, List, Optional
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda

from app.models import AuditScorecard, PolicyViolation, ResourceConfig
from app.vertex_agent_client import ask_agent

logger = logging.getLogger("cloudguard.orchestrator")

# Template for the Compliance Audit Prompt
AUDIT_PROMPT_TEMPLATE = """You are CloudGuard AI, an authoritative Google Cloud Security and Compliance Auditor.
Audit the following cloud resource configuration strictly against the compliance framework: {compliance_framework}.

TARGET RESOURCE:
- Resource Type: {resource_type}
- Resource Name: {resource_name}

CONFIGURATION ATTRIBUTES:
{config_details}

AUDIT INSTRUCTIONS:
1. Evaluate whether the resource meets the security and governance baseline of {compliance_framework}.
2. Explicitly cite rule references (e.g. CIS GCP Benchmark 5.2, HIPAA Security Rule § 164.312, etc.).
3. If public access is enabled or logging/encryption is missing, flag it as a violation.
4. Structure your response into a clear compliance scorecard:
   - STATUS: [PASS | FAIL | WARNING]
   - RISK_LEVEL: [CRITICAL | HIGH | MEDIUM | LOW | CLEAN]
   - SUMMARY: [Executive summary of security posture]
   - VIOLATIONS:
     * [Rule ID] - [Severity]: [Description] (Citation: [Source]) | Remediation: [gcloud command]
   - REMEDIATIONS:
     * [Actionable remediation steps or gcloud CLI commands]
"""

prompt_template = PromptTemplate(
    input_variables=[
        "compliance_framework",
        "resource_type",
        "resource_name",
        "config_details",
    ],
    template=AUDIT_PROMPT_TEMPLATE,
)


def format_config_details(config: ResourceConfig) -> str:
    """Formats a ResourceConfig object into structured text for the prompt."""
    lines: List[str] = []

    if config.public_access_prevention is not None:
        lines.append(f"- Public Access Prevention: {config.public_access_prevention}")
    if config.uniform_bucket_level_access is not None:
        lines.append(f"- Uniform Bucket-Level Access (UBLA): {'Enabled' if config.uniform_bucket_level_access else 'Disabled'}")
    if config.encryption_type is not None:
        lines.append(f"- Encryption: {config.encryption_type}")
    if config.versioning_enabled is not None:
        lines.append(f"- Object Versioning: {'Enabled' if config.versioning_enabled else 'Disabled'}")
    if config.logging_enabled is not None:
        lines.append(f"- Cloud Audit/Access Logging: {'Enabled' if config.logging_enabled else 'Disabled'}")
    if config.require_ssl is not None:
        lines.append(f"- Require SSL/TLS Enforced: {'Yes' if config.require_ssl else 'No'}")
    if config.authorized_networks:
        lines.append(f"- Authorized Networks: {', '.join(config.authorized_networks)}")

    if config.additional_attributes:
        for k, v in config.additional_attributes.items():
            lines.append(f"- {k}: {v}")

    if not lines:
        return "- No detailed security attributes provided (auditing based on resource defaults)."

    return "\n".join(lines)


def _call_vertex_agent_step(prompt_text: str) -> Dict[str, Any]:
    """LangChain Runnable step: Invokes the Vertex AI Agent Builder client.

    Uses RunnableLambda to keep it simple and standard without unnecessary custom LLM subclassing.
    """
    logger.info("LangChain Pipeline: Dispatching audit prompt to Vertex AI Agent step")
    # Calls ask_agent in vertex_agent_client.py
    return ask_agent(prompt_text=prompt_text)


def _parse_scorecard_step(agent_output: Dict[str, Any]) -> AuditScorecard:
    """LangChain Runnable step: Parses the agent response text and RAG metadata into an AuditScorecard."""
    response_text = agent_output.get("response_text", "")
    citations = list(agent_output.get("citations", []))

    # Parse status (PASS / FAIL / WARNING)
    status = "FAIL"
    status_match = re.search(r"STATUS\s*:\s*(PASS|FAIL|WARNING)", response_text, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).upper()
    elif "no violations found" in response_text.lower() or "compliant" in response_text.lower():
        status = "PASS"

    # Parse risk level
    risk_level = "MEDIUM"
    risk_match = re.search(r"RISK_LEVEL\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|CLEAN)", response_text, re.IGNORECASE)
    if risk_match:
        risk_level = risk_match.group(1).upper()
    elif status == "PASS":
        risk_level = "CLEAN"
    elif "critical" in response_text.lower():
        risk_level = "CRITICAL"
    elif "high" in response_text.lower():
        risk_level = "HIGH"

    # Parse summary
    summary_match = re.search(r"SUMMARY\s*:\s*([^\n]+(?:\n[^\n#]+)*?)(?=\n[A-Z_\s]+:|$)", response_text)
    if summary_match:
        summary = summary_match.group(1).strip()
    else:
        # First 200 characters as fallback summary
        summary = response_text[:200].strip() if response_text else "Audit completed."

    # Parse violations
    violations: List[PolicyViolation] = []
    violation_matches = re.finditer(
        r"^[*\-]\s*(?:\[(?P<rule_id>[^\]]+)\]|(?P<rule_id_alt>CIS-[A-Za-z0-9\.\-]+))\s*[-:]\s*(?:\[(?P<severity>[A-Za-z]+)\])?\s*:?\s*(?P<desc>[^|\n]+)(?:\|\s*Remediation:\s*(?P<remed>[^\n]+))?",
        response_text,
        re.MULTILINE,
    )
    for match in violation_matches:
        rule_id = match.group("rule_id") or match.group("rule_id_alt") or "POLICY-RULE"
        sev = match.group("severity") or "HIGH"
        desc = match.group("desc").strip().lstrip(": ")
        remed = match.group("remed").strip() if match.group("remed") else None

        # Check for inline citation
        citation = None
        cit_match = re.search(r"\(Citation:\s*([^)]+)\)", desc)
        if cit_match:
            citation = cit_match.group(1).strip()
            desc = desc.replace(cit_match.group(0), "").strip()

        violations.append(
            PolicyViolation(
                rule_id=rule_id.strip(),
                title=f"Violation in {rule_id.strip()}",
                severity=sev.upper(),
                description=desc,
                citation=citation,
                remediation=remed,
            )
        )

    # Parse remediation steps section (header must be at start of line or after newline)
    remediation_steps: List[str] = []
    remed_section = re.search(r"^(?:#+\s*)?REMEDIATIONS?:\s*(.*)", response_text, re.DOTALL | re.MULTILINE | re.IGNORECASE)
    if remed_section:
        remed_lines = remed_section.group(1).splitlines()
        for line in remed_lines:
            cleaned = line.strip().lstrip("*-123456789. ")
            if cleaned and not cleaned.startswith("#"):
                remediation_steps.append(cleaned)

    return AuditScorecard(
        status=status,
        risk_level=risk_level,
        summary=summary,
        violations=violations,
        citations=citations,
        remediation_steps=remediation_steps,
    )


# Construct the LangChain LCEL pipeline
# PromptTemplate -> RunnableLambda(format prompt string) -> RunnableLambda(ask_agent) -> RunnableLambda(parse)
def _format_prompt_runnable(inputs: Dict[str, Any]) -> str:
    return prompt_template.format(
        compliance_framework=inputs.get("compliance_framework", "CIS Google Cloud Foundations Benchmark v3.0"),
        resource_type=inputs.get("resource_type", "storage.googleapis.com/Bucket"),
        resource_name=inputs.get("resource_name", "unnamed-resource"),
        config_details=inputs.get("config_details", ""),
    )


audit_chain = (
    RunnableLambda(_format_prompt_runnable)
    | RunnableLambda(_call_vertex_agent_step)
    | RunnableLambda(_parse_scorecard_step)
)


def run_audit(
    resource_config: ResourceConfig,
    framework: str = "CIS Google Cloud Foundations Benchmark v3.0",
) -> AuditScorecard:
    """Entry point to execute the LangChain compliance audit pipeline.

    Args:
        resource_config: The cloud resource configuration to audit.
        framework: Compliance framework to evaluate against.

    Returns:
        AuditScorecard: Parsed and grounded compliance scorecard.
    """
    inputs = {
        "resource_type": resource_config.resource_type,
        "resource_name": resource_config.resource_name,
        "config_details": format_config_details(resource_config),
        "compliance_framework": framework,
    }
    logger.info("Executing LangChain audit pipeline for resource '%s'", resource_config.resource_name)
    return audit_chain.invoke(inputs)
