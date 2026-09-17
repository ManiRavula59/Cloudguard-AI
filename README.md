# CloudGuard AI — Automated Compliance & Policy RAG Agent

A production-grade, portfolio-ready security compliance microservice built for Google Cloud environments. It audits Google Cloud Platform (GCP) resource configurations against enterprise security baselines (e.g., CIS Google Cloud Foundations Benchmark v3.0, NIST SP 800-53, HIPAA, PCI-DSS) using **Vertex AI Agent Builder**, **RAG**, **LangChain orchestration**, **Google Workspace Sheets integration**, and **Gemini Vision multimodal extraction**.

---

## Architecture Decisions

### 1. Why LangChain sits between FastAPI and the Vertex AI Agent
In this architecture, LangChain is not a redundant wrapper around an API call — it acts as the **core orchestration and pipeline composition layer**:
* **Decoupling Orchestration from Vendor SDKs**: FastAPI routes handle HTTP serialization, CORS, and request validation. Directly hardcoding Vertex AI's `SessionsClient` or `DetectIntentRequest` inside FastAPI endpoints tightly couples endpoint handlers to Google's low-level protocol. LangChain abstracts prompt assembly, dynamic variable injection, and output parsing into decoupled Runnables.
* **Declarative Prompt Engineering (LCEL)**: Using LangChain's `PromptTemplate` provides strict input variable validation (`compliance_framework`, `resource_type`, `resource_name`, `config_details`) and versioned formatting.
* **Standardized Runnable Composition**: By wrapping `vertex_agent_client.ask_agent()` as a `RunnableLambda`, the compliance flow conforms to the standard LangChain Expression Language (LCEL) chain:
  $$\text{PromptTemplate} \longrightarrow \text{RunnableLambda(Agent Invocation)} \longrightarrow \text{OutputParser}$$
  This makes testing, pre-flight safety guardrails, prompt transformations, and downstream structured parsing composable and observable.
* **Preparation for Multi-Agent & Tool Workflows**: In an enterprise roadmap, compliance evaluation frequently requires multi-step routing (e.g. consulting a CVE vulnerability lookup tool or querying IAM policy analyzers). LangChain provides the foundational harness to expand from single-turn RAG to multi-agent supervisor architectures.

### 2. What is Real vs. What is Scoped (Honest Boundary)
* **What is 100% Real**:
  - **Vertex AI Agent Builder Integration**: Real `detect_intent` calls to Dialogflow CX / Vertex AI Agent Builder sessions with regional endpoints (`us-central1`, `global`).
  - **RAG Grounding**: Real semantic retrieval against compliance rulebook datastores indexed in Vertex AI Search.
  - **Gemini Multimodal Vision**: Real Google Generative AI vision calls that parse uploaded cloud console screenshots, strictly extracting only legible fields and defaulting unseen fields to `null`.
  - **Google Workspace Sheets API v4**: Real OAuth 2.0 and Sheets v4 client appending structured audit rows (`[timestamp, resource_name, scorecard_text]`) into an active Google Sheet.
  - **LangChain Pipeline & FastAPI Gateway**: Real Pydantic data contracts, CORS middleware, and non-blocking error resilience.
* **What is Deliberately Scoped Out**:
  - **No Live Cloud Infrastructure Scanning**: CloudGuard AI does **not** call Google Cloud's Asset Inventory or Security Command Center (SCC) APIs to scan live GCP projects. Resource configurations are either supplied as structured JSON payloads or extracted from cloud console screenshots. This boundary is intentional: CloudGuard AI evaluates *configurations*, avoiding elevated IAM permissions or intrusive scans across live client infrastructure.

### 3. Production Cloud Run Deployment Blueprint
In a production deployment, CloudGuard AI is designed to run as a serverless container on **Google Cloud Run**:
* **Serverless & Concurrency Tuning**: CloudRun scales to zero during idle periods to eliminate compute costs, while handling up to 80 concurrent audit requests per container instance with minimal latency.
* **IAM & Workload Identity**: Rather than mounting static JSON credentials, the Cloud Run service binds directly to a dedicated GCP Service Account (`cloudguard-backend-sa`) using Cloud Run runtime service accounts. Calls to Vertex AI Agent Builder authenticate transparently via Google Application Default Credentials (ADC).
* **Multi-Tenant Isolation**: In a multi-tenant enterprise scenario, CloudGuard AI can implement a per-tenant Service Account impersonation pattern: using Google Cloud IAM Credentials API to mint short-lived OAuth access tokens scoped exclusively to each tenant's specific Vertex AI Datastore and Google Workspace sheet.

---

## Project Structure

```
cloudguardai/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py                 # Pydantic Settings (.env configuration)
│   │   ├── models.py                 # Pydantic schemas (ResourceConfig, AuditScorecard)
│   │   ├── vertex_agent_client.py    # Vertex AI Agent Builder SessionsClient (detect_intent)
│   │   ├── langchain_orchestrator.py # LangChain PromptTemplate & RunnableLambda LCEL pipeline
│   │   ├── workspace_writer.py       # Google Sheets API v4 audit logger & OAuth guide
│   │   ├── vision_extractor.py       # Gemini Vision screenshot parser
│   │   └── main.py                   # FastAPI REST API endpoints (/audit, /audit-from-screenshot)
│   ├── tests/
│   │   ├── test_client.py            # Task 1 unit tests (LangChain, /audit, error handling)
│   │   ├── test_workspace.py         # Task 2 unit tests (Google Sheets logging)
│   │   └── test_vision.py            # Task 3 unit tests (Gemini Vision extraction)
│   ├── requirements.txt
│   └── .env.example
├── frontend/                         # React + Vite Interactive Compliance Dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── ...
├── architecture_and_flow.md          # Visual architecture & sequence diagrams
└── README.md
```

---

## Quickstart & Local Setup

### 1. Backend Setup

```bash
cd backend

# 1. Create and activate Python virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env with your GCP project ID, Vertex Agent ID, and Gemini API Key

# 4. Run the test suite
pytest tests/ -v

# 5. Start the FastAPI development server
uvicorn app.main:app --reload --port 8000
```

### 2. Google Workspace Sheets Setup (Optional for Sheet Logging)
Follow the detailed OAuth setup instructions documented at the top of [`backend/app/workspace_writer.py`](backend/app/workspace_writer.py):
1. Enable Google Sheets API in Google Cloud Console.
2. Download your OAuth 2.0 Desktop Client JSON as `credentials.json` into `backend/`.
3. Set `GOOGLE_SHEET_ID=<YOUR_SPREADSHEET_ID>` in `.env`.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status and version metadata |
| `GET` | `/api/config-status` | Inspects configured GCP and integration readiness |
| `POST` | `/audit` | Audits a structured `ResourceConfig` against a compliance framework |
| `POST` | `/audit-from-screenshot` | Multimodal endpoint: extracts config from screenshot and audits |

---

## Interview Talking Points

1. *"How did you ground your compliance agent?"*
   - Built a custom datastore in Vertex AI Agent Builder indexed with the official CIS Google Cloud Foundations Benchmark v3.0 PDF. The generative agent retrieves authoritative citations directly from the datastore.
2. *"Why not just call Vertex AI directly from FastAPI?"*
   - Separated orchestration concerns into LangChain using LCEL and `RunnableLambda`. This allows independent prompt templating, multi-stage parsing, and easy extension to tool-calling agents.
3. *"How do you handle unreadable fields from screenshots?"*
   - Prompted Gemini Vision explicitly with strict constraints: any attribute not clearly legible must be defaulted to `null` rather than hallucinated or inferred from default cloud states.
4. *"How resilient is your Google Workspace integration?"*
   - Google Sheets API writes are wrapped in non-blocking try/except blocks. Even if OAuth expires or a network timeout occurs, the client still receives the complete compliance scorecard with `logged_to_sheet: false` and actionable warning logs.
