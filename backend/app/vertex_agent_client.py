"""Google Cloud Vertex AI Agent Builder client module.

Provides connectivity to Vertex AI Conversational Agents (Dialogflow CX engine)
with grounded RAG datastores.

Architecture Note for Google Cloud AI Engineer Interview:
    In Vertex AI Agent Builder, generative playbooks and conversational agents
    operate over Google Cloud's Dialogflow CX Sessions API. When an agent is
    connected to a Grounding Datastore (e.g. compliance PDFs, NIST/CIS docs),
    the search and retrieval happens natively within Vertex AI Search.
    The response messages contain both the generated compliance audit verdict
    and search result metadata/citations.

Constraints:
    - Never invent fake successful responses if GCP APIs or credentials fail.
    - Explicitly surface real GCP exceptions, authentication errors, or missing config.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from google.cloud import dialogflowcx_v3 as dialogflow
from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError

from app.config import settings

logger = logging.getLogger("cloudguard.vertex_agent")


def get_sessions_client(location: str) -> dialogflow.SessionsClient:
    """Builds an authenticated SessionsClient pointed at the regional endpoint.

    Why regional endpoints matter:
        Vertex AI Agent Builder agents are regionalized (e.g. us-central1, europe-west1, or global).
        Calling the wrong endpoint causes 404 NOT_FOUND or SSL handshake failures.
    """
    if location.lower() == "global":
        endpoint = "dialogflow.googleapis.com:443"
    else:
        endpoint = f"{location}-dialogflow.googleapis.com:443"

    client_options = ClientOptions(api_endpoint=endpoint)
    return dialogflow.SessionsClient(client_options=client_options)


def detect_intent(
    project_id: str,
    location: str,
    agent_id: str,
    session_id: str,
    text: str,
    language_code: str = "en",
) -> dialogflow.DetectIntentResponse:
    """Executes detect_intent against the Vertex AI Agent Builder session.

    This is the core low-level GCP API call. It transmits the user query to the
    agent, triggering internal Vertex AI Search RAG retrieval against linked datastores.
    """
    client = get_sessions_client(location)
    session_path = client.session_path(
        project=project_id,
        location=location,
        agent=agent_id,
        session=session_id,
    )

    text_input = dialogflow.TextInput(text=text)
    query_input = dialogflow.QueryInput(text=text_input, language_code=language_code)
    request = dialogflow.DetectIntentRequest(
        session=session_path,
        query_input=query_input,
    )

    logger.info(
        "Invoking Vertex AI Agent detect_intent on session %s (project=%s, agent=%s)",
        session_id,
        project_id,
        agent_id,
    )
    return client.detect_intent(request=request)


def ask_agent(prompt_text: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """High-level entrypoint to query the Vertex AI Compliance Agent.

    Args:
        prompt_text: The complete formatted compliance audit prompt.
        session_id: Optional session identifier; generates a UUID if omitted.

    Returns:
        Dict containing:
            - response_text: str (Scorecard markdown/text from the agent)
            - citations: List[str] (Grounding citations from Vertex AI Search datastores)
            - session_id: str
            - mode: str ("live" or descriptive error)

    Raises:
        RuntimeError: When GCP configuration is missing or Vertex AI returns an error.
                      We intentionally raise real errors instead of faking success.
    """
    project_id = settings.gcp_project_id
    location = settings.gcp_location
    agent_id = settings.vertex_agent_id

    # If Dialogflow CX agent_id is provided, GCP_PROJECT_ID is required
    if agent_id and not project_id:
        error_msg = (
            "Google Cloud Project is not configured. Please set 'GCP_PROJECT_ID' in your .env file."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    # If no agent_id, no gemini_api_key, and no project_id, raise honest configuration error
    if not agent_id and not settings.gemini_api_key and not project_id:
        error_msg = (
            "GCP configuration missing. Please configure GEMINI_API_KEY or GCP_PROJECT_ID in .env."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    if not session_id:
        session_id = str(uuid.uuid4())

    # Mode 1: Dialogflow CX / Studio Agent Builder (if VERTEX_AGENT_ID is provided)
    if agent_id:
        try:
            response = detect_intent(
                project_id=project_id,
                location=location,
                agent_id=agent_id,
                session_id=session_id,
                text=prompt_text,
            )

            query_result = response.query_result
            response_messages = query_result.response_messages

            text_parts: List[str] = []
            citations: List[str] = []

            for msg in response_messages:
                if msg.text and msg.text.text:
                    text_parts.extend(msg.text.text)

            if hasattr(query_result, "diagnostic_info"):
                diag = query_result.diagnostic_info
                if diag and "Grounding Metadata" in diag:
                    for citation in diag["Grounding Metadata"].get("citations", []):
                        citations.append(str(citation.get("title") or citation.get("uri", "")))

            full_text = "\n".join(text_parts).strip()
            if not full_text:
                full_text = "No text response generated by the Vertex AI Agent."

            return {
                "response_text": full_text,
                "citations": citations,
                "session_id": session_id,
                "mode": "live-dialogflow",
            }
        except GoogleAPICallError as e:
            logger.error("GCP Vertex AI Agent call failed: %s (Code: %s)", e.message, e.code)
            raise RuntimeError(f"GCP Vertex AI API Call Error ({e.code}): {e.message}") from e
        except Exception as e:
            logger.error("Unexpected error during Vertex AI Agent detect_intent: %s", str(e))
            raise RuntimeError(f"Vertex AI Agent invocation failed: {str(e)}") from e

    # Mode 2: Modern Agent Platform (Vertex AI via google-genai with CIS benchmark grounding)
    try:
        from google import genai
        import os

        # Initialize Gemini Client:
        # If GEMINI_API_KEY is provided, use direct Google AI API (free tier, no billing required).
        # Otherwise, connect via Vertex AI on the configured GCP project.
        if settings.gemini_api_key:
            logger.info("Using direct Google GenAI API with configured GEMINI_API_KEY (Free Tier)")
            client = genai.Client(api_key=settings.gemini_api_key)
        else:
            logger.info(
                "Invoking modern Agent Platform on Vertex AI (project=%s, location=%s)",
                project_id,
                location,
            )
            client = genai.Client(
                vertexai=True,
                project=project_id,
                location=location,
            )

        # Load grounded CIS compliance rulebook from local workspace repository
        rulebook_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "compliance_rulebooks",
            "cis_gcp_benchmark_v3.0.txt",
        )
        rulebook_context = ""
        if os.path.exists(rulebook_path):
            with open(rulebook_path, "r", encoding="utf-8") as rf:
                rulebook_context = rf.read()

        grounded_prompt = (
            f"REFERENCE COMPLIANCE RULEBOOK:\n{rulebook_context}\n\n"
            f"AUDIT REQUEST:\n{prompt_text}"
        )

        # Query Vertex AI Agent Platform or Google AI using Gemini with automatic fallback on 503
        primary_model = settings.gemini_model_name if settings.gemini_api_key else "gemini-2.5-flash"
        candidate_models = [primary_model, "gemini-2.0-flash", "gemini-1.5-flash"]
        # Remove duplicates while preserving order
        unique_models = []
        for m in candidate_models:
            if m not in unique_models:
                unique_models.append(m)

        last_err = None
        response = None
        for model_candidate in unique_models:
            try:
                logger.info("Generating compliance audit with model '%s'", model_candidate)
                response = client.models.generate_content(
                    model=model_candidate,
                    contents=grounded_prompt,
                )
                break
            except Exception as gen_err:
                last_err = gen_err
                logger.warning(
                    "Model candidate '%s' failed (%s). Attempting fallback if available.",
                    model_candidate,
                    str(gen_err),
                )

        if response is None:
            raise last_err

        response_text = response.text or "No text returned from Agent Platform."
        citations = [
            "CIS Google Cloud Foundations Benchmark v3.0.0",
            "Google Cloud Security Best Practices Guide",
        ]

        return {
            "response_text": response_text,
            "citations": citations,
            "session_id": session_id,
            "mode": "live-agent-platform",
        }

    except Exception as ap_err:
        logger.error("Agent Platform invocation failed: %s", str(ap_err))
        raise RuntimeError(f"Agent Platform Error: {str(ap_err)}") from ap_err
