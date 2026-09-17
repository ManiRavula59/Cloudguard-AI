"""Retrieval-Augmented Generation (RAG) Retriever for CloudGuard AI.

Implements a multi-framework vector similarity search engine over compliance rulebooks
and regulatory standards using ChromaDB as the persistent vector store and Google's
embedding model (gemini-embedding-001) via the Google GenAI SDK.

Supported Frameworks & Collections:
- CIS Google Cloud Foundations Benchmark (`cis_gcp_benchmark`)
- NIST Special Publication 800-53 Rev. 5 (`nist_sp_800_53`)
- HIPAA Security Rule 45 CFR Part 164 (`hipaa_part_164`)

Key Features:
- PDF and text-based rule/control chunking (rule boundaries, control IDs, regulatory sections).
- Persistent local ChromaDB storage in `backend/.chroma_db/`.
- Safe batch embedding with Google GenAI API and backoff retry on 429 quota limits.
- Dynamic framework routing based on selected compliance framework.
- Top-k similarity retrieval producing grounded citations and rule excerpts.
"""

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

import chromadb
from app.config import settings

logger = logging.getLogger("cloudguard.rag")

DEFAULT_COLLECTION_NAME = "cis_gcp_benchmark"
EMBEDDING_MODEL_NAME = "gemini-embedding-001"


def get_rulebooks_dir() -> str:
    """Returns the absolute path to the compliance rulebooks directory."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(
        os.path.join(base_dir, "..", "..", "compliance_rulebooks")
    )


def get_default_paths() -> tuple[str, str]:
    """Returns absolute paths for the persistent vector DB and default rulebook file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    persist_dir = os.path.join(base_dir, "..", ".chroma_db")
    rulebook_path = os.path.join(
        get_rulebooks_dir(),
        "cis_gcp_benchmark_v3.0.txt",
    )
    return os.path.abspath(persist_dir), os.path.abspath(rulebook_path)


def resolve_framework_collection(framework_name: Optional[str]) -> str:
    """Resolves an incoming compliance framework name to its ChromaDB collection identifier."""
    if not framework_name:
        return DEFAULT_COLLECTION_NAME

    fn_lower = framework_name.lower().strip()
    if "hipaa" in fn_lower or "164" in fn_lower:
        return "hipaa_part_164"
    elif "nist" in fn_lower or "800-53" in fn_lower:
        return "nist_sp_800_53"
    elif "cis" in fn_lower or "cloud foundations" in fn_lower:
        return "cis_gcp_benchmark"
    else:
        # Fallback to CIS benchmark collection for unrecognized or general frameworks
        return DEFAULT_COLLECTION_NAME


# ---------------------------------------------------------------------------
# PDF and Text Rule Chunkers
# ---------------------------------------------------------------------------

def load_and_chunk_cis_rulebook(rulebook_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Chunks CIS Google Cloud Foundations Benchmark into discrete rule records."""
    _, default_rulebook = get_default_paths()
    target_path = rulebook_path or default_rulebook

    if not os.path.exists(target_path):
        logger.warning("CIS rulebook not found at path: %s", target_path)
        return []

    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()

    sections = re.split(r"(SECTION\s+\d+:\s+[^\n]+)", content)
    chunks: List[Dict[str, Any]] = []

    for i in range(1, len(sections), 2):
        current_section = sections[i].strip()
        sec_body = sections[i + 1]

        rule_blocks = re.split(r"(?m)(?=^\d+\.\d+\s+Ensure)", sec_body)
        for block in rule_blocks:
            block_clean = block.strip().strip("-").strip()
            if not block_clean:
                continue

            rid_match = re.search(r"Rule ID:\s*([A-Za-z0-9\.\-]+)", block_clean)
            sev_match = re.search(r"Severity:\s*([A-Za-z]+)", block_clean)
            first_line = block_clean.splitlines()[0].strip()

            rule_id = rid_match.group(1) if rid_match else f"CIS-{len(chunks)+1}"
            severity = sev_match.group(1) if sev_match else "HIGH"

            full_chunk_text = f"{current_section}\n{block_clean}"
            citation = f"{rule_id} - {first_line}"

            chunks.append(
                {
                    "rule_id": rule_id,
                    "title": first_line,
                    "section": current_section,
                    "severity": severity,
                    "citation": citation,
                    "content": full_chunk_text,
                }
            )

    logger.info("Loaded and chunked %d CIS compliance rules from %s", len(chunks), target_path)
    return chunks


# Alias for backward compatibility with existing tests
load_and_chunk_rulebook = load_and_chunk_cis_rulebook


def load_and_chunk_hipaa_pdf(pdf_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Chunks HIPAA Security & Privacy Rule (45 CFR Part 164) PDF into substantive sections."""
    try:
        import pypdf
    except ImportError:
        logger.error("pypdf is required to parse HIPAA PDF. Please install pypdf.")
        return []

    target_path = pdf_path or os.path.join(
        get_rulebooks_dir(),
        "45 CFR Part 164 (up to date as of 9-15-2026).pdf",
    )

    if not os.path.exists(target_path):
        logger.warning("HIPAA PDF rulebook not found at path: %s", target_path)
        return []

    reader = pypdf.PdfReader(target_path)
    full_text = "\n".join([p.extract_text() or "" for p in reader.pages])

    pattern = r"(?:§|\u00a7|\ufffd)\s*(164\.\d+)\s+([^\n]+)"
    matches = list(re.finditer(pattern, full_text))

    # Focus on Subpart C Security Standards and core Privacy safeguard requirements
    security_sections = {
        "164.306", "164.308", "164.310", "164.312",
        "164.314", "164.316", "164.502", "164.530"
    }
    extracted_by_id: Dict[str, Dict[str, Any]] = {}

    for i, match in enumerate(matches):
        sec_num = match.group(1)
        sec_title = match.group(2).strip().rstrip(".")
        if sec_num not in security_sections:
            continue

        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        chunk_text = full_text[start:end].strip()

        # Keep the substantive section body if multiple matches appear (e.g. index matrix vs full body)
        if sec_num not in extracted_by_id or len(chunk_text) > len(extracted_by_id[sec_num]["content"]):
            rule_id = f"HIPAA-{sec_num}"
            citation = f"HIPAA 45 CFR § {sec_num} - {sec_title}"
            extracted_by_id[sec_num] = {
                "rule_id": rule_id,
                "title": f"§ {sec_num} {sec_title}",
                "section": "HIPAA 45 CFR Part 164 Security & Privacy Rule",
                "severity": "CRITICAL" if sec_num in ("164.312", "164.308") else "HIGH",
                "citation": citation,
                "content": chunk_text[:2500],
            }

    chunks = list(extracted_by_id.values())
    logger.info("Loaded and chunked %d substantive HIPAA sections from %s", len(chunks), target_path)
    return chunks


def load_and_chunk_nist_pdf(pdf_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Chunks NIST SP 800-53 Rev. 5 PDF into key cloud security and privacy control records."""
    try:
        import pypdf
    except ImportError:
        logger.error("pypdf is required to parse NIST PDF. Please install pypdf.")
        return []

    target_path = pdf_path or os.path.join(
        get_rulebooks_dir(),
        "NIST.SP.800-53r5.pdf",
    )

    if not os.path.exists(target_path):
        logger.warning("NIST SP 800-53 PDF rulebook not found at path: %s", target_path)
        return []

    reader = pypdf.PdfReader(target_path)
    full_text = "\n".join([p.extract_text() or "" for p in reader.pages])

    # Core cloud security, access control, audit, and encryption controls
    core_nist_controls = {
        "AC-2", "AC-3", "AC-4", "AC-6", "AC-17",
        "AU-2", "AU-3", "AU-4", "AU-6", "AU-12",
        "CM-6", "CM-7", "CM-8",
        "IA-2", "IA-4", "IA-5",
        "MP-4", "SC-7", "SC-8", "SC-12", "SC-13", "SC-28", "SI-4"
    }

    pattern = r"(?m)^([A-Z]{2}-\d+)\s+([A-Z][A-Z\s\(\)\,\-\/]{3,})(?=\n)"
    matches = list(re.finditer(pattern, full_text))
    chunks: List[Dict[str, Any]] = []
    seen_ctrls = set()

    for i, match in enumerate(matches):
        ctrl_id = match.group(1).strip()
        ctrl_title = match.group(2).strip().title()

        if ctrl_id not in core_nist_controls or ctrl_id in seen_ctrls:
            continue
        seen_ctrls.add(ctrl_id)

        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        chunk_text = full_text[start:end].strip()

        if len(chunk_text) > 80:
            rule_id = f"NIST-{ctrl_id}"
            citation = f"NIST SP 800-53 Rev. 5 - {ctrl_id}: {ctrl_title}"
            chunks.append(
                {
                    "rule_id": rule_id,
                    "title": f"{ctrl_id} {ctrl_title}",
                    "section": f"NIST Control Family {ctrl_id.split('-')[0]}",
                    "severity": "CRITICAL" if ctrl_id in ("AC-3", "SC-28", "AU-2") else "HIGH",
                    "citation": citation,
                    "content": chunk_text[:2500],
                }
            )

    logger.info("Loaded and chunked %d core NIST 800-53 controls from %s", len(chunks), target_path)
    return chunks


def load_chunks_for_collection(collection_name: str) -> List[Dict[str, Any]]:
    """Dispatches chunk loading based on collection name."""
    if collection_name == "hipaa_part_164":
        return load_and_chunk_hipaa_pdf()
    elif collection_name == "nist_sp_800_53":
        return load_and_chunk_nist_pdf()
    else:
        return load_and_chunk_cis_rulebook()


# ---------------------------------------------------------------------------
# Embeddings Generation
# ---------------------------------------------------------------------------

def embed_texts(texts: List[str], api_key: Optional[str] = None) -> List[List[float]]:
    """Embeds a list of strings in batches using Google GenAI with backoff retry on 429."""
    if not texts:
        return []

    from google import genai

    active_key = api_key or settings.gemini_api_key
    if not active_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. Cannot generate RAG embeddings."
        )

    client = genai.Client(api_key=active_key)
    batch_size = 25
    all_embeddings: List[List[float]] = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        success = False
        for attempt in range(4):
            try:
                response = client.models.embed_content(
                    model=EMBEDDING_MODEL_NAME,
                    contents=batch,
                )
                all_embeddings.extend([e.values for e in response.embeddings])
                success = True
                break
            except Exception as err:
                err_str = str(err)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                    wait_sec = (attempt + 1) * 4
                    logger.warning(
                        "Gemini embedding quota reached (429). Retrying in %ds (attempt %d/4)...",
                        wait_sec,
                        attempt + 1,
                    )
                    time.sleep(wait_sec)
                else:
                    logger.error("Embedding call failed: %s", err_str)
                    raise err

        if not success:
            raise RuntimeError(
                f"Failed to generate embeddings for batch {i//batch_size} after 4 retries due to quota limits."
            )

        if i + batch_size < len(texts):
            time.sleep(0.5)

    return all_embeddings


# ---------------------------------------------------------------------------
# ChromaDB Multi-Collection Management & Retrieval
# ---------------------------------------------------------------------------

def get_or_init_vector_store(
    persist_dir: Optional[str] = None,
    rulebook_path: Optional[str] = None,
    api_key: Optional[str] = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> chromadb.Collection:
    """Retrieves existing ChromaDB collection or indexes chunks on first startup."""
    default_persist, _ = get_default_paths()
    target_persist = persist_dir or default_persist

    os.makedirs(target_persist, exist_ok=True)
    chroma_client = chromadb.PersistentClient(path=target_persist)
    collection = chroma_client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    if collection.count() == 0:
        logger.info(
            "ChromaDB collection '%s' is empty. Indexing rule chunks into %s...",
            collection_name,
            target_persist,
        )
        chunks = load_chunks_for_collection(collection_name)
        if not chunks:
            logger.warning("No chunks extracted for collection '%s'. Vector store remains empty.", collection_name)
            return collection

        texts = [c["content"] for c in chunks]
        embeddings = embed_texts(texts, api_key=api_key)

        collection.add(
            ids=[c["rule_id"] for c in chunks],
            documents=texts,
            metadatas=[
                {
                    "rule_id": c["rule_id"],
                    "title": c["title"],
                    "section": c["section"],
                    "severity": c["severity"],
                    "citation": c["citation"],
                }
                for c in chunks
            ],
            embeddings=embeddings,
        )
        logger.info(
            "Successfully indexed %d rule chunks into ChromaDB collection '%s'",
            len(chunks),
            collection_name,
        )
    else:
        logger.debug(
            "ChromaDB collection '%s' loaded from disk with %d indexed rules.",
            collection_name,
            collection.count(),
        )

    return collection


def retrieve_relevant_rule_records(
    query: str,
    framework: Optional[str] = None,
    top_k: int = 3,
    api_key: Optional[str] = None,
    persist_dir: Optional[str] = None,
    collection_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves top-k matching rule chunks from the framework's ChromaDB collection."""
    clean_query = query.strip()
    if not clean_query:
        return []

    target_collection = collection_name or resolve_framework_collection(framework)

    collection = get_or_init_vector_store(
        persist_dir=persist_dir,
        api_key=api_key,
        collection_name=target_collection,
    )
    if collection.count() == 0:
        logger.warning("Vector store '%s' is empty. No rules available for retrieval.", target_collection)
        return []

    query_embeddings = embed_texts([clean_query], api_key=api_key)
    if not query_embeddings:
        return []

    actual_k = min(top_k, collection.count())
    results = collection.query(
        query_embeddings=query_embeddings,
        n_results=actual_k,
    )

    records: List[Dict[str, Any]] = []
    ids = results.get("ids", [[]])[0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0] if "distances" in results else [0.0] * len(ids)

    for i, rule_id in enumerate(ids):
        doc = docs[i] if i < len(docs) else ""
        meta = metas[i] if i < len(metas) else {}
        dist = distances[i] if i < len(distances) else 0.0

        records.append(
            {
                "rule_id": rule_id,
                "title": meta.get("title", rule_id),
                "section": meta.get("section", "General"),
                "severity": meta.get("severity", "HIGH"),
                "citation": meta.get("citation", f"{target_collection} {rule_id}"),
                "content": doc,
                "distance": dist,
            }
        )

    retrieved_rule_ids = [r["rule_id"] for r in records]
    logger.info(
        "RAG Retrieval [%s]: query='%s' retrieved %d rule chunks: %s",
        target_collection,
        clean_query[:100],
        len(records),
        retrieved_rule_ids,
    )
    return records


def retrieve_relevant_rules(
    query: str,
    framework: Optional[str] = None,
    top_k: int = 3,
    api_key: Optional[str] = None,
    persist_dir: Optional[str] = None,
    collection_name: Optional[str] = None,
) -> List[str]:
    """Retrieves the top-k most relevant rulebook chunk text strings for a query."""
    records = retrieve_relevant_rule_records(
        query=query,
        framework=framework,
        top_k=top_k,
        api_key=api_key,
        persist_dir=persist_dir,
        collection_name=collection_name,
    )
    return [r["content"] for r in records]
