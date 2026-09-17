"""Application configuration module for CloudGuard AI.

Defines environment variables, Google Cloud Platform (GCP) configurations,
Vertex AI Agent Builder identifiers, Gemini Vision settings, and Google Sheets
integration details using Pydantic Settings.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration for CloudGuard AI services.

    Attributes:
        app_name: Display name of the microservice.
        app_version: Current release version.
        environment: Runtime environment ('development', 'staging', 'production').
        gcp_project_id: The GCP project where the Vertex AI Agent Builder is hosted.
        gcp_location: The region of the Agent Builder instance (e.g. 'us-central1' or 'global').
        vertex_agent_id: The unique Dialogflow CX / Vertex AI Agent ID.
        gemini_api_key: Direct API key for Gemini Vision multimodal config extraction.
        google_sheet_id: Target Google Spreadsheet ID for compliance logging.
        google_oauth_credentials_path: Path to the OAuth client secret credentials JSON file.
        google_oauth_token_path: Path where user OAuth refresh tokens are stored.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    app_name: str = "CloudGuard AI"
    app_version: str = "1.0.0"
    environment: str = "development"

    # Google Cloud Vertex AI Configuration
    gcp_project_id: Optional[str] = None
    gcp_location: str = "us-central1"
    vertex_agent_id: Optional[str] = None

    # Multimodal Vision (Gemini direct API)
    gemini_api_key: Optional[str] = None
    gemini_model_name: str = "gemini-2.5-flash"

    # Google Workspace Sheets Integration
    google_sheet_id: Optional[str] = None
    google_oauth_credentials_path: str = "credentials.json"
    google_oauth_token_path: str = "token.json"


settings = Settings()
