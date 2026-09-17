"""Retrieval-Augmented Generation (RAG) Retriever for CloudGuard AI.

Implements a vector similarity search engine over compliance rulebooks using
ChromaDB as the persistent vector store and Google's embedding model
(gemini-embedding-001 / text-embedding-004) via the Google GenAI SDK.

Key Features:
- Rule-boundary aware chunking (splits by canonical CIS rule headers).
- Local persistent embedding cache in `.chroma_db/` to prevent redundant embeddings.
- Top-k similarity retrieval so only relevant compliance rules are passed to the LLM.
- Inspectable logging of retrieved rule IDs and section headers.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

import chromadb
from app.config import settings

logger = logging.getLogger("cloudguard.rag")

DEFAULT_COLLECTION_NAME = "cis_gcp_benchmark_v3"
EMBEDDING_MODEL_CANDIDATES = ["gemini-embedding-001", "text-embedding-004"]


def get_default_paths() -> tuple[str, str]:
    """Returns absolute paths for the persistent vector DB and rulebook file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    persist_dir = os.path.join(base_dir, "..", ".chroma_db")
    rulebook_path = os.path.join(
        base_dir,
        "..",
        "..",
        "compliance_rulebooks",
        "cis_gcp_benchmark_v3.0.txt",
    )
    return os.path.abspath(persist_dir), os.path.abspath(rulebook_path)


def load_and_chunk_rulebook(rulebook_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Chunks the compliance rulebook by logical rule boundaries.

    Inspects sections and individual rule headers (e.g. '1.1 Ensure...', 'Rule ID: CIS-GCP-X.X')
    to create self-contained compliance rule chunks with rich metadata.
    """
    _, default_rulebook = get_default_paths()
    target_path = rulebook_path or default_rulebook

    if not os.path.exists(target_path):
        logger.warning("Compliance rulebook not found at path: %s", target_path)
        return []

    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Split document by major SECTION headers
    sections = re.split(r"(SECTION\s+\d+:\s+[^\n]+)", content)
    chunks: List[Dict[str, Any]] = []

    for i in range(1, len(sections), 2):
        current_section = sections[i].strip()
        sec_body = sections[i + 1]

        # Split rules within this section by rule number pattern (e.g. '1.1 Ensure...', '2.1 Ensure...')
        rule_blocks = re.split(r"(?m)(?=^\d+\.\d+\s+Ensure)", sec_body)
        for block in rule_blocks:
            block_clean = block.strip().strip("-").strip()
            if not block_clean:
                continue

            rid_match = re.search(r"Rule ID:\s*([A-Za-z0-9\.\-]+)", block_clean)
            sev_match = re.search(r"Severity:\s*([A-Za-z]+)", block_clean)
            first_line = block_clean.splitlines()[0].strip()

            rule_id = rid_match.group(1) if rid_match else f"RULE-{len(chunks)+1}"
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

    logger.info("Loaded and chunked %d compliance rules from %s", len(chunks), target_path)
    return chunks


def embed_texts(texts: List[str], api_key: Optional[str] = None) -> List[List[float]]:
    """Embeds a list of strings using Google GenAI embedding models."""
    if not texts:
        return []

    from google import genai

    active_key = api_key or settings.gemini_api_key
    if not active_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. Cannot generate RAG embeddings."
        )

    client = genai.Client(api_key=active_key)
    last_err: Optional[Exception] = None

    for model_name in EMBEDDING_MODEL_CANDIDATES:
        try:
            response = client.models.embed_content(
                model=model_name,
                contents=texts,
            )
            embeddings = [e.values for e in response.embeddings]
            return embeddings
        except Exception as err:
            last_err = err
            logger.warning("Embedding with '%s' failed (%s). Trying candidate...", model_name, str(err))

    raise RuntimeError(f"All candidate embedding models failed. Last error: {str(last_err)}") from last_err


def get_or_init_vector_store(
    persist_dir: Optional[str] = None,
    rulebook_path: Optional[str] = None,
    api_key: Optional[str] = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> chromadb.Collection:
    """Retrieves existing ChromaDB collection or indexes rulebook chunks on first startup."""
    default_persist, default_rulebook = get_default_paths()
    target_persist = persist_dir or default_persist
    target_rulebook = rulebook_path or default_rulebook

    os.makedirs(target_persist, exist_ok=True)
    chroma_client = chromadb.PersistentClient(path=target_persist)
    collection = chroma_client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    if collection.count() == 0:
        logger.info(
            "ChromaDB collection '%s' is empty. Indexing rulebook chunks from %s into %s...",
            collection_name,
            target_rulebook,
            target_persist,
        )
        chunks = load_and_chunk_rulebook(target_rulebook)
        if not chunks:
            logger.warning("No chunks extracted from rulebook. Vector store remains empty.")
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
    top_k: int = 3,
    api_key: Optional[str] = None,
    persist_dir: Optional[str] = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> List[Dict[str, Any]]:
    """Retrieves top-k matching rule chunks with metadata for a given compliance query."""
    clean_query = query.strip()
    if not clean_query:
        return []

    collection = get_or_init_vector_store(
        persist_dir=persist_dir,
        api_key=api_key,
        collection_name=collection_name,
    )
    if collection.count() == 0:
        logger.warning("Vector store is empty. No rules available for retrieval.")
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
                "citation": meta.get("citation", f"CIS Benchmark {rule_id}"),
                "content": doc,
                "distance": dist,
            }
        )

    retrieved_rule_ids = [r["rule_id"] for r in records]
    logger.info(
        "RAG Retrieval: query='%s' retrieved %d rule chunks: %s",
        clean_query[:100],
        len(records),
        retrieved_rule_ids,
    )
    return records


def retrieve_relevant_rules(
    query: str,
    top_k: int = 3,
    api_key: Optional[str] = None,
    persist_dir: Optional[str] = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> List[str]:
    """Retrieves the top-k most relevant rulebook chunk text strings for a query."""
    records = retrieve_relevant_rule_records(
        query=query,
        top_k=top_k,
        api_key=api_key,
        persist_dir=persist_dir,
        collection_name=collection_name,
    )
    return [r["content"] for r in records]
