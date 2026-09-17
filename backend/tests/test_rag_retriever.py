"""Test suite verifying real RAG retrieval accuracy and query discrimination.

Proves:
1. The rulebook is chunked cleanly by rule boundaries into 14 canonical CIS rules.
2. ChromaDB similarity search actually discriminates between different security domains
   (e.g. CMEK Encryption vs MFA Authentication vs Database SSL vs Public Access Prevention).
3. The retrieved top-k sets are distinct, not identical or static.
"""

import pytest
from app.rag_retriever import (
    load_and_chunk_rulebook,
    load_and_chunk_hipaa_pdf,
    load_and_chunk_nist_pdf,
    resolve_framework_collection,
    retrieve_relevant_rule_records,
    retrieve_relevant_rules,
)


def test_rulebook_chunking():
    """Verifies that the rulebook is parsed into 14 distinct rules with metadata."""
    chunks = load_and_chunk_rulebook()
    assert len(chunks) == 14, f"Expected 14 rule chunks, got {len(chunks)}"

    rule_ids = {c["rule_id"] for c in chunks}
    # Check key expected CIS benchmark rules
    expected_rules = {
        "CIS-GCP-1.1",
        "CIS-GCP-1.2",
        "CIS-GCP-1.3",
        "CIS-GCP-5.2",
        "CIS-GCP-5.3",
        "CIS-GCP-5.4",
        "CIS-GCP-5.5",
        "CIS-GCP-5.6",
        "CIS-GCP-6.1",
        "CIS-GCP-6.2",
        "CIS-GCP-6.3",
        "CIS-GCP-4.1",
        "CIS-GCP-4.2",
        "CIS-GCP-2.1",
    }
    assert expected_rules.issubset(rule_ids), f"Missing expected rules: {expected_rules - rule_ids}"

    for chunk in chunks:
        assert chunk["rule_id"], "Each chunk must have a rule_id"
        assert chunk["title"], "Each chunk must have a title"
        assert chunk["section"], "Each chunk must have a section"
        assert chunk["content"], "Each chunk must have content"


def test_retrieval_discrimination():
    """Proves that ChromaDB vector retrieval discriminates semantically between queries.

    A query for CMEK encryption must return CIS-GCP-5.4.
    A query for MFA must return CIS-GCP-1.2.
    A query for Cloud SQL SSL must return CIS-GCP-6.1.
    A query for GCS public access must return CIS-GCP-5.2.
    """
    # 1. Query for Customer-Managed Encryption Keys
    records_encryption = retrieve_relevant_rule_records(
        "Customer-Managed Encryption Keys CMEK Cloud KMS key ring",
        top_k=2,
    )
    assert len(records_encryption) >= 1
    top_enc_rule = records_encryption[0]["rule_id"]
    assert top_enc_rule == "CIS-GCP-5.4", f"Expected CIS-GCP-5.4 for CMEK, got {top_enc_rule}"

    # 2. Query for Multi-Factor Authentication
    records_mfa = retrieve_relevant_rule_records(
        "Multi-Factor Authentication MFA 2-Step Verification for administrative users",
        top_k=2,
    )
    assert len(records_mfa) >= 1
    top_mfa_rule = records_mfa[0]["rule_id"]
    assert top_mfa_rule == "CIS-GCP-1.2", f"Expected CIS-GCP-1.2 for MFA, got {top_mfa_rule}"

    # 3. Query for Cloud SQL database SSL
    records_sql = retrieve_relevant_rule_records(
        "Cloud SQL database instance require SSL TLS incoming connections",
        top_k=2,
    )
    assert len(records_sql) >= 1
    top_sql_rule = records_sql[0]["rule_id"]
    assert top_sql_rule == "CIS-GCP-6.1", f"Expected CIS-GCP-6.1 for SQL SSL, got {top_sql_rule}"

    # 4. Query for Storage Public Access Prevention
    records_public = retrieve_relevant_rule_records(
        "Public Access Prevention enforced on Cloud Storage bucket allUsers",
        top_k=2,
    )
    assert len(records_public) >= 1
    top_public_rule = records_public[0]["rule_id"]
    assert top_public_rule == "CIS-GCP-5.2", f"Expected CIS-GCP-5.2 for Public Access, got {top_public_rule}"

    # 5. Discrimination assertion: verify the retrieved sets are NOT identical
    enc_ids = {r["rule_id"] for r in records_encryption}
    mfa_ids = {r["rule_id"] for r in records_mfa}
    sql_ids = {r["rule_id"] for r in records_sql}
    pub_ids = {r["rule_id"] for r in records_public}

    assert enc_ids != mfa_ids, "Encryption and MFA returned identical rule sets"
    assert enc_ids != sql_ids, "Encryption and SQL returned identical rule sets"
    assert mfa_ids != pub_ids, "MFA and Public Access returned identical rule sets"
    assert sql_ids != pub_ids, "SQL and Public Access returned identical rule sets"


def test_retrieve_relevant_rules_returns_strings():
    """Verifies that retrieve_relevant_rules returns a list of chunk strings."""
    string_chunks = retrieve_relevant_rules(
        "Cloud SQL database backups Point-in-time recovery",
        top_k=2,
    )
    assert isinstance(string_chunks, list)
    assert len(string_chunks) == 2
    assert all(isinstance(s, str) for s in string_chunks)
    assert any("CIS-GCP-6.3" in s for s in string_chunks), "Expected backup rule CIS-GCP-6.3 in returned chunks"


def test_dynamic_citations_match_retrieved_chunks():
    """Proves that citations are strictly derived from retrieved rule chunks, not hardcoded."""
    records = retrieve_relevant_rule_records("Ensure Cloud Storage buckets have Public Access Prevention", top_k=2)
    assert len(records) > 0
    expected_citations = [r["citation"] for r in records if r.get("citation")]

    # Citations must reflect real retrieved rule headers
    assert any("CIS-GCP-5.2" in c for c in expected_citations)
    assert not any("Google Cloud Security Best Practices Guide" in c for c in expected_citations), "Hardcoded fake citation found!"


def test_hipaa_pdf_chunking_and_retrieval():
    """Verifies that HIPAA 45 CFR Part 164 PDF is parsed and technical safeguards are retrievable."""
    chunks = load_and_chunk_hipaa_pdf()
    assert len(chunks) >= 7, f"Expected at least 7 HIPAA sections, got {len(chunks)}"

    rule_ids = {c["rule_id"] for c in chunks}
    assert "HIPAA-164.312" in rule_ids, "Expected HIPAA Technical Safeguards (164.312)"
    assert "HIPAA-164.308" in rule_ids, "Expected HIPAA Administrative Safeguards (164.308)"

    # Query for transmission security and encryption
    records = retrieve_relevant_rule_records(
        query="Technical safeguards encryption and decryption of electronic protected health information ePHI",
        framework="HIPAA Security Rule 45 CFR Part 164",
        top_k=2,
    )
    assert len(records) >= 1
    top_rule_ids = [r["rule_id"] for r in records]
    assert any("312" in rid for rid in top_rule_ids), f"Expected 164.312 in retrieved HIPAA rules, got {top_rule_ids}"
    assert any("164.312" in r["citation"] for r in records), f"Expected 164.312 in citations, got {[r['citation'] for r in records]}"


def test_nist_pdf_chunking_and_retrieval():
    """Verifies that NIST SP 800-53 Rev 5 PDF is parsed into distinct control chunks and retrievable."""
    chunks = load_and_chunk_nist_pdf()
    assert len(chunks) >= 20, f"Expected at least 20 NIST controls, got {len(chunks)}"

    rule_ids = {c["rule_id"] for c in chunks}
    assert "NIST-AC-3" in rule_ids, "Expected NIST AC-3 Access Enforcement"
    assert "NIST-SC-28" in rule_ids, "Expected NIST SC-28 Protection of Information at Rest"

    # Query for Protection of Information at Rest
    records = retrieve_relevant_rule_records(
        query="Protection of information at rest cryptographic mechanisms",
        framework="NIST Special Publication 800-53 (Rev. 5)",
        top_k=2,
    )
    assert len(records) >= 1
    top_rule_ids = [r["rule_id"] for r in records]
    assert any("SC-28" in rid or "SC-13" in rid or "AC-3" in rid for rid in top_rule_ids), f"Got {top_rule_ids}"
    assert "NIST SP 800-53 Rev. 5" in records[0]["citation"]


def test_multi_framework_routing():
    """Proves that querying for encryption routes to the exact selected framework collection."""
    # Query identical topic across 3 different frameworks
    query = "Encryption at rest cryptographic key management CMEK KMS"

    cis_records = retrieve_relevant_rule_records(
        query=query,
        framework="CIS Google Cloud Foundations Benchmark v3.0",
        top_k=1,
    )
    nist_records = retrieve_relevant_rule_records(
        query=query,
        framework="NIST Special Publication 800-53 (Rev. 5)",
        top_k=1,
    )
    hipaa_records = retrieve_relevant_rule_records(
        query=query,
        framework="HIPAA Security Rule 45 CFR Part 164",
        top_k=1,
    )

    assert len(cis_records) == 1
    assert len(nist_records) == 1
    assert len(hipaa_records) == 1

    # CIS returns CIS rule
    assert cis_records[0]["rule_id"].startswith("CIS-")
    # NIST returns NIST control
    assert nist_records[0]["rule_id"].startswith("NIST-")
    # HIPAA returns HIPAA regulation section
    assert hipaa_records[0]["rule_id"].startswith("HIPAA-")

    # Assert collections are completely disjoint
    assert cis_records[0]["citation"] != nist_records[0]["citation"]
    assert nist_records[0]["citation"] != hipaa_records[0]["citation"]

