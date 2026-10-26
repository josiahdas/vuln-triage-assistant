"""
Retrieval evaluation: measures whether the RAG layer surfaces the right
guidance for a given query, using a small hand-labeled golden set.

This is the piece that separates "we built a RAG demo" from "we measured
whether our RAG actually retrieves the right thing" -- a real engineering
question with a real answer, not just a vibe check.

Metrics:
- Precision@k: of the top-k retrieved chunks, what fraction come from an
  expected source file?
- Hit@k: did at least one expected source appear in the top-k?
- MRR (Mean Reciprocal Rank): how high up was the first relevant hit?

Run: python -m app.eval.retrieval_eval
"""
from dataclasses import dataclass, field
from app.rag.index import retrieve_guidance


@dataclass
class GoldenQuery:
    vendor: str
    query: str
    expected_sources: list[str]  # any of these counts as a "relevant" hit
    expected_keywords: list[str] = field(default_factory=list)  # content-level check
    note: str = ""


# Hand-labeled golden set. Each query is a realistic CVE-description-style
# input paired with the source file(s) that should reasonably answer it.
# Kept small and honest rather than padded -- a golden set you can defend
# in an interview beats one that just inflates a metric.
GOLDEN_SET: list[GoldenQuery] = [
    GoldenQuery(
        vendor="paloalto",
        query="Buffer overflow in the PAN-OS management web interface allows remote code execution",
        expected_sources=["paloalto_hardening.txt"],
        expected_keywords=["management interface", "untrusted zones"],
        note="Should retrieve PAN-OS management-interface exposure guidance",
    ),
    GoldenQuery(
        vendor="paloalto",
        query="GlobalProtect portal authentication bypass vulnerability",
        expected_sources=["paloalto_hardening.txt"],
        expected_keywords=["globalprotect"],
        note="Should retrieve GlobalProtect-specific guidance, not generic PAN-OS advice",
    ),
    GoldenQuery(
        vendor="cisco",
        query="Cisco ASA VPN remote access authentication vulnerability",
        expected_sources=["cisco_hardening.txt"],
        expected_keywords=["asa", "multi-factor", "vpn"],
        note="Should retrieve ASA VPN MFA guidance",
    ),
    GoldenQuery(
        vendor="cisco",
        query="Cisco IOS XE web UI privilege escalation",
        expected_sources=["cisco_hardening.txt"],
        expected_keywords=["web-based management", "ios xe"],
        note="Should retrieve IOS XE web management UI guidance",
    ),
    GoldenQuery(
        vendor="fortinet",
        query="FortiOS SSL-VPN unauthenticated remote code execution",
        expected_sources=["fortinet_hardening.txt"],
        expected_keywords=["ssl-vpn"],
        note="Should retrieve SSL-VPN specific guidance -- this is the highest-stakes case",
    ),
    GoldenQuery(
        vendor="juniper",
        query="Junos J-Web authentication bypass",
        expected_sources=["juniper_hardening.txt"],
        expected_keywords=["j-web"],
        note="Should retrieve J-Web guidance",
    ),
    # Adversarial / cross-vendor case: query mentions a Cisco-sounding term
    # but is filtered to paloalto -- retrieval should NOT return Cisco
    # guidance even if it's semantically closer, because the vendor filter
    # is a hard constraint, not a preference.
    GoldenQuery(
        vendor="paloalto",
        query="Smart Install unauthenticated configuration manipulation",
        expected_sources=["paloalto_hardening.txt"],
        expected_keywords=[],  # no PAN-OS doc content actually addresses this -- see note
        note="Vendor filter correctness check: query text is Cisco-flavored but vendor=paloalto. "
             "Keyword check intentionally empty: PAN-OS doc has no relevant match, so this checks "
             "that the LLM layer (not retrieval) is responsible for saying 'no direct guidance found.'",
    ),
]


def evaluate_retrieval(k: int = 3) -> dict:
    """
    Note on precision@k: with the current knowledge base (one doc per
    vendor), file-level precision/hit-rate is trivially 1.0 once the
    vendor filter is applied -- it can't discriminate quality. The
    keyword_hit metric below is the more meaningful signal here: does
    the *specific chunk content* returned actually address the query,
    not just "did it come from the right vendor's file." This limitation
    (and why file-level metrics alone would be misleading) is worth
    calling out explicitly rather than reporting a hollow 100% precision.
    """
    results = []
    reciprocal_ranks = []

    for gq in GOLDEN_SET:
        hits = retrieve_guidance(gq.vendor, gq.query, n_results=k)
        hit_sources = [h["source"] for h in hits]
        hit_texts = [h["text"].lower() for h in hits]

        relevant_flags = [src in gq.expected_sources for src in hit_sources]
        precision_at_k = sum(relevant_flags) / len(relevant_flags) if relevant_flags else 0.0
        hit_at_k = any(relevant_flags)

        rank = next((i + 1 for i, flag in enumerate(relevant_flags) if flag), None)
        reciprocal_ranks.append(1 / rank if rank else 0.0)

        # Keyword check: does ANY retrieved chunk contain ANY expected keyword?
        # Skipped (marked N/A) for queries with no expected_keywords defined.
        if gq.expected_keywords:
            combined_text = " ".join(hit_texts)
            keyword_hit = any(kw.lower() in combined_text for kw in gq.expected_keywords)
        else:
            keyword_hit = None

        results.append({
            "vendor": gq.vendor,
            "query": gq.query,
            "expected_sources": gq.expected_sources,
            "retrieved_sources": hit_sources,
            "precision_at_k": round(precision_at_k, 2),
            "hit_at_k": hit_at_k,
            "keyword_hit": keyword_hit,
            "note": gq.note,
        })

    keyword_checked = [r for r in results if r["keyword_hit"] is not None]
    keyword_hit_rate = (
        round(sum(1 for r in keyword_checked if r["keyword_hit"]) / len(keyword_checked), 3)
        if keyword_checked else None
    )

    return {
        "k": k,
        "num_queries": len(GOLDEN_SET),
        "mean_precision_at_k": round(sum(r["precision_at_k"] for r in results) / len(results), 3),
        "hit_rate_at_k": round(sum(1 for r in results if r["hit_at_k"]) / len(results), 3),
        "mrr": round(sum(reciprocal_ranks) / len(reciprocal_ranks), 3),
        "keyword_hit_rate": keyword_hit_rate,
        "per_query": results,
    }


def print_report(report: dict):
    print(f"Retrieval eval (k={report['k']}, {report['num_queries']} queries)")
    print(f"  Mean Precision@{report['k']}: {report['mean_precision_at_k']}  "
          f"(NOTE: trivially high with 1 doc/vendor -- see keyword_hit_rate for real signal)")
    print(f"  Hit Rate@{report['k']}:       {report['hit_rate_at_k']}")
    print(f"  MRR:                    {report['mrr']}")
    print(f"  Keyword hit rate:       {report['keyword_hit_rate']}  (content-level relevance check)")
    print()
    for r in report["per_query"]:
        kw_status = "N/A" if r["keyword_hit"] is None else ("PASS" if r["keyword_hit"] else "FAIL")
        print(f"  [keyword: {kw_status}] ({r['vendor']}) {r['query'][:55]}...")
        if r["note"]:
            print(f"         note: {r['note']}")


if __name__ == "__main__":
    report = evaluate_retrieval(k=3)
    print_report(report)
