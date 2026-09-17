"""FastAPI application entrypoint for CloudGuard AI.

Exposes REST APIs for automated compliance audits, LangChain orchestration,
and system status diagnostics.
"""

import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import AuditRequest, AuditResponse, ResourceConfig, ScreenshotAuditResponse
from app.langchain_orchestrator import run_audit, format_config_details, prompt_template
from app.workspace_writer import log_audit_to_sheet
from app.vision_extractor import extract_config_from_image

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudguard.api")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Automated Compliance & Policy RAG Agent for Google Cloud Platform",
)

# Enable CORS for React Vite development and production origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust to specific frontend origins in strict production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def build_audit_prompt(
    resource_config: ResourceConfig,
    framework: str = "CIS Google Cloud Foundations Benchmark v3.0",
) -> str:
    """Constructs the compliance audit prompt string.

    Backward Compatibility Note:
        Retained so existing client scripts, CLI callers, or previous test suites
        continue working seamlessly while under the hood delegating to the
        standardized LangChain PromptTemplate.
    """
    return prompt_template.format(
        compliance_framework=framework,
        resource_type=resource_config.resource_type,
        resource_name=resource_config.resource_name,
        config_details=format_config_details(resource_config),
    )


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Health check endpoint confirming API service readiness."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@app.get("/api/config-status", tags=["System"])
def config_status() -> Dict[str, Any]:
    """Inspects active GCP configurations and integration readiness.

    Surfaces whether real GCP credentials and services are bound without
    leaking secret keys.
    """
    return {
        "gcp_project_id_configured": bool(settings.gcp_project_id),
        "gcp_location": settings.gcp_location,
        "vertex_agent_configured": bool(settings.vertex_agent_id),
        "gemini_api_key_configured": bool(settings.gemini_api_key),
        "google_sheets_configured": bool(settings.google_sheet_id),
    }


@app.post("/audit", response_model=AuditResponse, tags=["Compliance Audit"])
def audit_resource(request: AuditRequest) -> AuditResponse:
    """Audits a cloud resource configuration against a compliance rulebook.

    Architecture Note:
        Routes the request through the LangChain orchestration pipeline
        (PromptTemplate -> RunnableLambda(ask_agent) -> OutputParser)
        which interfaces directly with Google Cloud's Vertex AI Agent Builder.
    """
    resource_config = request.resource_config
    framework = request.compliance_framework

    logger.info(
        "Received audit request for resource '%s' against framework '%s'",
        resource_config.resource_name,
        framework,
    )

    try:
        scorecard = run_audit(resource_config=resource_config, framework=framework)

        # Non-blocking Google Workspace Sheets logging (Task 2)
        logged_to_sheet = False
        sheet_error = None
        try:
            scorecard_text_for_sheet = (
                f"[{scorecard.status} | Risk: {scorecard.risk_level}] "
                f"{scorecard.summary} | Violations: {len(scorecard.violations)}"
            )
            logged_to_sheet = log_audit_to_sheet(
                resource_name=resource_config.resource_name,
                scorecard_text=scorecard_text_for_sheet,
                sheet_id=settings.google_sheet_id,
            )
        except Exception as ws_err:
            sheet_error = str(ws_err)
            logger.warning(
                "Google Workspace Sheet logging failed for '%s' (non-blocking): %s",
                resource_config.resource_name,
                sheet_error,
            )

        return AuditResponse(
            resource_name=resource_config.resource_name,
            framework=framework,
            scorecard=scorecard,
            logged_to_sheet=logged_to_sheet,
            sheet_error=sheet_error,
            agent_mode="live",
        )

    except RuntimeError as re_err:
        logger.error("Audit processing runtime error: %s", str(re_err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(re_err),
        )
    except Exception as e:
        logger.error("Unexpected error in /audit endpoint: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution error: {str(e)}",
        )


@app.post(
    "/audit-from-screenshot",
    response_model=ScreenshotAuditResponse,
    tags=["Compliance Audit"],
)
async def audit_from_screenshot(
    file: UploadFile = File(..., description="Cloud console settings screenshot"),
    compliance_framework: str = Form(
        default="CIS Google Cloud Foundations Benchmark v3.0",
        description="Compliance standard to audit against",
    ),
) -> ScreenshotAuditResponse:
    """Audits a cloud resource by extracting its settings from a console screenshot.

    Multimodal Architecture:
        1. Employs Gemini Vision to extract a ResourceConfig from the uploaded image.
        2. Strictly identifies which attributes were visibly extracted vs defaulted to null.
        3. Passes the extracted config into the EXACT same LangChain audit pipeline
           used by the /audit endpoint (avoiding duplicate logic).
    """
    logger.info("Received screenshot upload: '%s' (%s)", file.filename, file.content_type)

    # 1. Read uploaded image bytes
    try:
        image_bytes = await file.read()
        if not image_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )
    except Exception as read_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read image file: {str(read_err)}",
        )

    # 2. Extract ResourceConfig using Gemini Vision
    try:
        extracted_config, extracted_fields, null_fields = extract_config_from_image(image_bytes=image_bytes)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Vision parsing error: {str(val_err)}",
        )
    except RuntimeError as rt_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(rt_err),
        )

    # 3. Route through the EXACT same LangChain audit pipeline (zero duplication)
    audit_request = AuditRequest(
        resource_config=extracted_config,
        compliance_framework=compliance_framework,
    )
    audit_result = audit_resource(audit_request)

    return ScreenshotAuditResponse(
        extracted_config=extracted_config,
        extracted_fields=extracted_fields,
        null_fields=null_fields,
        audit_result=audit_result,
    )
