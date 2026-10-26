"""
RAG layer: chunk + embed the hardening knowledge base into ChromaDB,
and retrieve relevant guidance for a given Finding.

Uses ChromaDB's default local embedding function (all-MiniLM-L6-v2 via
sentence-transformers) so this runs fully offline with no embedding API
cost -- a reasonable engineering tradeoff to call out: swap in a hosted
embedding model if retrieval quality needs to improve later.

Run to build the index: python -m app.rag.index
"""
import os
import glob
import logging
import chromadb

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

KB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "knowledge_base")
CHROMA_DIR = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma")
COLLECTION_NAME = "hardening_guidance"


def _get_client():
    return chromadb.PersistentClient(path=CHROMA_DIR)


def _chunk_document(text: str, chunk_size: int = 500, overlap: int = 100) -> list[str]:
    """Simple sliding-window chunking by characters. Good enough for
    short, structured docs like these; a real corpus of long PDFs would
    want sentence/paragraph-aware chunking instead."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return [c.strip() for c in chunks if c.strip()]


def build_index():
    client = _get_client()
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass
    collection = client.create_collection(COLLECTION_NAME)

    doc_paths = glob.glob(os.path.join(KB_DIR, "*.txt"))
    log.info(f"Found {len(doc_paths)} knowledge base documents")

    ids, documents, metadatas = [], [], []
    for path in doc_paths:
        with open(path) as f:
            content = f.read()

        # first 3 lines are simple frontmatter: vendor/product/topic
        lines = content.split("\n")
        vendor = lines[0].replace("vendor:", "").strip()
        product = lines[1].replace("product:", "").strip()
        body = "\n".join(lines[4:])  # skip frontmatter + '---'

        chunks = _chunk_document(body)
        for i, chunk in enumerate(chunks):
            doc_id = f"{os.path.basename(path)}::chunk{i}"
            ids.append(doc_id)
            documents.append(chunk)
            metadatas.append({"vendor": vendor, "product": product, "source_file": os.path.basename(path)})

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    log.info(f"Indexed {len(ids)} chunks into collection '{COLLECTION_NAME}'")


def retrieve_guidance(vendor: str, query_text: str, n_results: int = 3) -> list[dict]:
    """
    Retrieve the most relevant hardening guidance chunks for a given
    vendor + query (typically the CVE description or a short summary
    of the finding).
    """
    client = _get_client()
    collection = client.get_collection(COLLECTION_NAME)
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where={"vendor": vendor},
    )
    hits = []
    for doc, meta, dist in zip(
        results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        hits.append({"text": doc, "source": meta["source_file"], "distance": dist})
    return hits


if __name__ == "__main__":
    build_index()
