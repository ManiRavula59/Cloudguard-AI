"""Google Workspace Integration: Google Sheets Audit Logger for CloudGuard AI.

================================================================================
GOOGLE CLOUD CONSOLE OAUTH 2.0 SETUP INSTRUCTIONS:
================================================================================
To enable automated audit logging to Google Sheets:

1. Enable the Google Sheets API:
   - Go to Google Cloud Console (https://console.cloud.google.com).
   - Navigate to 'APIs & Services' > 'Library'.
   - Search for 'Google Sheets API' and click 'Enable'.

2. Configure the OAuth Consent Screen:
   - Navigate to 'APIs & Services' > 'OAuth consent screen'.
   - Choose User Type 'External' (or 'Internal' if using Google Workspace organization).
   - Fill in the required App name (e.g. 'CloudGuard AI') and developer contact email.
   - In 'Scopes', add: `https://www.googleapis.com/auth/spreadsheets`.
   - In 'Test users', add your Google email address so your account can authorize the app.

3. Generate OAuth 2.0 Credentials:
   - Navigate to 'APIs & Services' > 'Credentials'.
   - Click '+ CREATE CREDENTIALS' > 'OAuth client ID'.
   - Select Application type: 'Desktop app'.
   - Name it 'CloudGuard AI Desktop Client' and click 'Create'.
   - Click 'DOWNLOAD JSON' and rename the downloaded file to `credentials.json`.
   - Place `credentials.json` in the root of your project directory (`cloudguardai/credentials.json`
     or `backend/credentials.json`).

4. Prepare your Google Sheet:
   - Open Google Sheets (https://sheets.new) and create a new spreadsheet.
   - Copy the Sheet ID from the browser URL:
     https://docs.google.com/spreadsheets/d/<SHEET_ID>/edit
   - Add this ID to your `.env` file as: `GOOGLE_SHEET_ID=<SHEET_ID>`.
   - (Optional) In row 1 of the sheet, create header columns:
     [Timestamp, Resource Name, Audit Scorecard]

5. First-Time Run Authorization:
   - When the first audit runs, a local browser prompt will open to authorize CloudGuard AI.
   - Once approved, an authorized `token.json` is cached locally for all subsequent calls.
================================================================================
"""

import datetime
import logging
import os
from typing import Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.config import settings

logger = logging.getLogger("cloudguard.workspace")

# Google Sheets API Scope for appending rows
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def get_sheets_service(
    credentials_path: Optional[str] = None,
    token_path: Optional[str] = None,
):
    """Initializes and returns an authenticated Google Sheets API v4 service client.

    Attempts to load cached credentials from `token.json`. If missing or expired,
    initiates the OAuth 2.0 InstalledAppFlow using `credentials.json`.

    Returns:
        Resource: Authenticated Google Sheets API v4 client.

    Raises:
        FileNotFoundError: If `credentials.json` is missing and no valid token exists.
        RuntimeError: If authentication or authorization flow fails.
    """
    creds_file = credentials_path or settings.google_oauth_credentials_path
    token_file = token_path or settings.google_oauth_token_path

    # Check root directory fallback if path is relative
    if not os.path.exists(creds_file):
        parent_candidate = os.path.join("..", creds_file)
        if os.path.exists(parent_candidate):
            creds_file = parent_candidate

    creds = None

    # Step 1: Check for previously cached token
    if os.path.exists(token_file):
        try:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            logger.info("Loaded cached Google Sheets OAuth token from %s", token_file)
        except Exception as e:
            logger.warning("Failed to load existing token file %s: %s", token_file, str(e))
            creds = None

    # Step 2: Refresh expired token or run new OAuth login flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired Google Sheets OAuth token...")
            try:
                creds.refresh(Request())
                with open(token_file, "w", encoding="utf-8") as token_out:
                    token_out.write(creds.to_json())
            except Exception as ref_err:
                logger.warning("Token refresh failed (%s). Triggering fresh login.", ref_err)
                creds = None

        if not creds:
            if not os.path.exists(creds_file):
                raise FileNotFoundError(
                    f"Google Workspace OAuth credentials file not found at '{creds_file}'. "
                    "Please follow the OAuth setup instructions at the top of workspace_writer.py."
                )

            logger.info("Launching OAuth 2.0 InstalledAppFlow for Google Sheets API...")
            flow = InstalledAppFlow.from_client_secrets_file(creds_file, SCOPES)
            creds = flow.run_local_server(port=0)

            # Persist the newly obtained token for subsequent requests
            with open(token_file, "w", encoding="utf-8") as token_out:
                token_out.write(creds.to_json())
            logger.info("Cached new Google Sheets OAuth token to %s", token_file)

    return build("sheets", "v4", credentials=creds)


def log_audit_to_sheet(
    resource_name: str,
    scorecard_text: str,
    sheet_id: Optional[str] = None,
    service: Optional[object] = None,
) -> bool:
    """Appends a new compliance audit record row to the specified Google Sheet.

    Row Format per specification:
        [timestamp, resource_name, scorecard_text]

    Args:
        resource_name: Name of the audited cloud resource (e.g. 'prod-public-user-data').
        scorecard_text: Formatted audit scorecard summary or full evaluation text.
        sheet_id: Google Spreadsheet ID (defaults to settings.google_sheet_id).
        service: Optional pre-built Sheets service client (used in testing or dependency injection).

    Returns:
        bool: True if row was successfully appended, False otherwise.

    Raises:
        ValueError: If sheet_id is not provided or configured.
        Exception: If Google Sheets API append fails.
    """
    target_sheet_id = sheet_id or settings.google_sheet_id
    if not target_sheet_id:
        raise ValueError(
            "Target Google Sheet ID is missing. Configure 'GOOGLE_SHEET_ID' in .env or pass sheet_id."
        )

    timestamp_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Construct row payload strictly per project requirements: [timestamp, resource_name, scorecard_text]
    row_values = [
        timestamp_iso,
        resource_name,
        scorecard_text,
    ]

    sheets_client = service or get_sheets_service()

    logger.info(
        "Appending audit record to Google Sheet ID '%s' for resource '%s'",
        target_sheet_id,
        resource_name,
    )

    body = {"values": [row_values]}
    range_name = "Sheet1!A:C"

    try:
        result = (
            sheets_client.spreadsheets()
            .values()
            .append(
                spreadsheetId=target_sheet_id,
                range=range_name,
                valueInputOption="USER_ENTERED",
                insertDataOption="INSERT_ROWS",
                body=body,
            )
            .execute()
        )

        updates = result.get("updates", {})
        updated_rows = updates.get("updatedRows", 0)
        logger.info(
            "Successfully appended %d row(s) to Google Sheet (Updated Range: %s)",
            updated_rows,
            updates.get("updatedRange", "unknown"),
        )
        return True

    except HttpError as http_err:
        logger.error(
            "Google Sheets API HttpError (%s): %s",
            http_err.resp.status,
            http_err.content.decode("utf-8") if hasattr(http_err, "content") else str(http_err),
        )
        raise RuntimeError(f"Google Sheets API Error ({http_err.resp.status}): {http_err.reason}") from http_err
    except Exception as e:
        logger.error("Failed to append row to Google Sheet '%s': %s", target_sheet_id, str(e))
        raise
