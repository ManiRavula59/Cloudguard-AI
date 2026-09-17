"""Multimodal Vision Extraction module for CloudGuard AI.

Uses direct Gemini Vision API (via google-generativeai) to extract structured
ResourceConfig attributes from cloud console screenshots.

Interview Architecture Note:
    This is intentionally decoupled from the Vertex AI RAG Agent:
    - Gemini Vision performs pure multimodal perception (image-to-JSON extraction).
    - The extracted config is then fed into the LangChain orchestration layer
      (the exact same pipeline used by direct API submissions), ensuring zero
      duplication of compliance rule evaluation.
"""

import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import google.generativeai as genai
from PIL import Image

from app.config import settings
from app.models import ResourceConfig

logger = logging.getLogger("cloudguard.vision")

VISION_EXTRACTION_PROMPT = """You are CloudGuard AI's Cloud Console Vision Specialist.
Analyze the provided cloud console screenshot (e.g., Google Cloud Storage, Cloud SQL, Compute Engine, or IAM settings).

Extract all visible configuration settings into a valid JSON object matching this exact schema:
{
  "resource_type": "storage.googleapis.com/Bucket",
  "resource_name": "<resource name or ID visible in the image>",
  "public_access_prevention": "<enforced | inherited | unspecified | null>",
  "uniform_bucket_level_access": <true | false | null>,
  "encryption_type": "<CMEK | GOOGLE_MANAGED | CUSTOMER_SUPPLIED | null>",
  "versioning_enabled": <true | false | null>,
  "logging_enabled": <true | false | null>,
  "require_ssl": <true | false | null>,
  "authorized_networks": [<list of visible IP strings>] or null,
  "additional_attributes": { <any other clearly visible key-value settings> }
}

CRITICAL EXTRACTION CONSTRAINTS:
1. Only extract attributes that are clearly visible and legible in the screenshot.
2. If any field is not visible, obscured, or uncertain, you MUST set its value to null.
3. Never guess or invent values based on cloud defaults.
4. Output ONLY valid JSON (no markdown backticks, no explanations).
"""


def _clean_json_text(raw_text: str) -> str:
    """Removes markdown code block formatting or extraneous whitespace."""
    text = raw_text.strip()
    # Strip markdown code blocks like ```json ... ```
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_config_from_image(
    image_bytes: bytes,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    model_override: Optional[Any] = None,
) -> Tuple[ResourceConfig, List[str], List[str]]:
    """Extracts a ResourceConfig from screenshot image bytes using Gemini Vision.

    Args:
        image_bytes: Raw bytes of the uploaded image file.
        api_key: Optional Gemini API key override (defaults to settings.gemini_api_key).
        model_name: Model identifier (defaults to settings.gemini_model_name).
        model_override: Mock or test model instance for unit testing.

    Returns:
        Tuple containing:
            - ResourceConfig: Extracted Pydantic configuration object.
            - List[str]: Fields successfully extracted from the image.
            - List[str]: Fields that were not visible and defaulted to null.

    Raises:
        RuntimeError: If Gemini API key is missing or the Vision API fails.
        ValueError: If the image cannot be decoded or valid JSON cannot be parsed.
    """
    # 1. Validate image data
    try:
        pil_image = Image.open(io.BytesIO(image_bytes))
    except Exception as img_err:
        raise ValueError(f"Invalid image file: {str(img_err)}") from img_err

    # 2. Configure Gemini Vision client
    active_key = api_key or settings.gemini_api_key
    target_model = model_name or settings.gemini_model_name

    if model_override is not None:
        logger.info("Using mock model_override for vision extraction")
        try:
            response = model_override.generate_content([VISION_EXTRACTION_PROMPT, pil_image])
            response_text = response.text if hasattr(response, "text") else str(response)
        except Exception as api_err:
            logger.error("Gemini Vision mock call failed: %s", str(api_err))
            raise RuntimeError(f"Gemini Vision API error: {str(api_err)}") from api_err
    else:
        if not active_key:
            raise RuntimeError(
                "Gemini API key is not configured. Set 'GEMINI_API_KEY' in your .env file "
                "or pass an api_key to perform multimodal screenshot extraction."
            )
        logger.info("Sending screenshot (%dx%d) to Gemini Vision (%s)", pil_image.width, pil_image.height, target_model)
        try:
            from google import genai
            client = genai.Client(api_key=active_key)
            response = client.models.generate_content(
                model=target_model,
                contents=[VISION_EXTRACTION_PROMPT, pil_image],
            )
            response_text = response.text or ""
        except Exception as api_err:
            logger.error("Gemini Vision API call failed: %s", str(api_err))
            raise RuntimeError(f"Gemini Vision API error: {str(api_err)}") from api_err

    # 4. Parse extracted JSON
    cleaned_json = _clean_json_text(response_text)
    try:
        data: Dict[str, Any] = json.loads(cleaned_json)
    except json.JSONDecodeError as json_err:
        logger.error("Failed to decode JSON from Gemini Vision output: %s", cleaned_json)
        raise ValueError(f"Gemini Vision returned unparseable JSON: {cleaned_json[:200]}") from json_err

    # 5. Determine extracted vs null fields
    monitored_fields = [
        "resource_type",
        "resource_name",
        "public_access_prevention",
        "uniform_bucket_level_access",
        "encryption_type",
        "versioning_enabled",
        "logging_enabled",
        "require_ssl",
        "authorized_networks",
    ]

    extracted_fields: List[str] = []
    null_fields: List[str] = []

    for field in monitored_fields:
        val = data.get(field)
        if val is not None:
            extracted_fields.append(field)
        else:
            null_fields.append(field)

    # Ensure required resource_name exists
    if not data.get("resource_name"):
        data["resource_name"] = "screenshot-extracted-resource"
        null_fields.append("resource_name")
        if "resource_name" in extracted_fields:
            extracted_fields.remove("resource_name")

    if not data.get("resource_type"):
        data["resource_type"] = "storage.googleapis.com/Bucket"

    config = ResourceConfig(**data)
    logger.info(
        "Vision extraction complete: %d extracted fields, %d null fields",
        len(extracted_fields),
        len(null_fields),
    )
    return config, extracted_fields, null_fields
