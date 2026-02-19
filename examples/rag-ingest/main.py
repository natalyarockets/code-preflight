"""RAG Ingest: upload documents → chunk → embed → store in vector DB.

Tier 1 batch app. Takes uploaded documents (PDF or text), splits them into
chunks, generates embeddings via OpenAI, and upserts to Pinecone. Outputs
an ingest summary as a JSON artifact.

Required secrets (env vars):
    OPENAI_API_KEY      — for text-embedding-3-small
    PINECONE_API_KEY    — for vector upsert (optional — without it, saves to file only)
    PINECONE_INDEX_HOST — full index host URL (optional)

Input files: PDF or .txt documents placed in the input directory.
Output: ingest_summary.json with chunk count, token estimate, and per-file stats.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import httpx
from openai import OpenAI
from pypdf import PdfReader

# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------

PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY", "")
PINECONE_INDEX_HOST = os.environ.get("PINECONE_INDEX_HOST", "")
EMBEDDING_MODEL = "text-embedding-3-small"

CHUNK_SIZE = 800       # chars per chunk
CHUNK_OVERLAP = 200    # overlap between chunks
BATCH_SIZE = 96        # embeddings per API call


def extract_text(file_path: Path) -> str:
    """Extract text from a PDF or text file."""
    if file_path.suffix.lower() == ".pdf":
        reader = PdfReader(str(file_path))
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
        return "\n\n".join(pages)
    else:
        return file_path.read_text(encoding="utf-8", errors="replace")


def chunk_text(text: str, source: str) -> list[dict]:
    """Split text into overlapping chunks with metadata."""
    chunks = []
    start = 0
    idx = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunk_text_str = text[start:end]
        if chunk_text_str.strip():
            chunks.append({
                "id": hashlib.sha256(f"{source}:{idx}".encode()).hexdigest()[:16],
                "text": chunk_text_str,
                "metadata": {
                    "source": source,
                    "chunk_index": idx,
                    "char_start": start,
                    "char_end": min(end, len(text)),
                },
            })
            idx += 1
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


def embed_chunks(chunks: list[dict], client: OpenAI) -> list[dict]:
    """Generate embeddings for chunks via OpenAI API."""
    results = []
    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]
        texts = [c["text"] for c in batch]
        print(f"  Embedding batch {i // BATCH_SIZE + 1} ({len(texts)} chunks)...")

        response = client.embeddings.create(input=texts, model=EMBEDDING_MODEL)

        for chunk, emb in zip(batch, response.data):
            chunk["embedding"] = emb.embedding
            results.append(chunk)

    return results


def upsert_to_pinecone(chunks: list[dict]) -> int:
    """Upsert embedded chunks to Pinecone index. Returns count upserted."""
    upserted = 0
    with httpx.Client() as http:
        for i in range(0, len(chunks), BATCH_SIZE):
            batch = chunks[i : i + BATCH_SIZE]
            vectors = [
                {
                    "id": c["id"],
                    "values": c["embedding"],
                    "metadata": {**c["metadata"], "text": c["text"]},
                }
                for c in batch
            ]
            print(f"  Upserting batch {i // BATCH_SIZE + 1} ({len(vectors)} vectors)...")

            resp = http.post(
                f"{PINECONE_INDEX_HOST}/vectors/upsert",
                headers={"Api-Key": PINECONE_API_KEY},
                json={"vectors": vectors},
                timeout=30,
            )
            resp.raise_for_status()
            upserted += len(vectors)

    return upserted


def find_input_files(input_dir: Path) -> list[Path]:
    """Find all PDF and text files in the input directory."""
    extensions = {".pdf", ".txt", ".md", ".csv", ".json"}
    files = []
    for f in sorted(input_dir.iterdir()):
        if f.is_file() and f.suffix.lower() in extensions:
            files.append(f)
    return files


def main():
    # Resolve input/output directories
    input_dir = Path(os.environ.get("LA_INPUT_DIR", "inputs"))
    output_dir = Path(os.environ.get("LA_OUTPUT_DIR", "outputs"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Init OpenAI client
    openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    has_pinecone = bool(PINECONE_API_KEY and PINECONE_INDEX_HOST)
    if not has_pinecone:
        print("NOTE: Pinecone credentials not set — embeddings will be saved to file only")

    # Find input files
    files = find_input_files(input_dir)
    if not files:
        print(f"ERROR: No input files found in {input_dir}", file=sys.stderr)
        print(f"  Supported: .pdf, .txt, .md, .csv, .json", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} input file(s)")

    # Process each file
    all_chunks: list[dict] = []
    file_stats: list[dict] = []

    for file_path in files:
        print(f"\nProcessing: {file_path.name}")

        # Extract text
        text = extract_text(file_path)
        print(f"  Extracted {len(text)} chars")

        if not text.strip():
            print(f"  Skipping (empty)")
            file_stats.append({"file": file_path.name, "chars": 0, "chunks": 0, "status": "empty"})
            continue

        # Chunk
        chunks = chunk_text(text, source=file_path.name)
        print(f"  Created {len(chunks)} chunks")

        all_chunks.extend(chunks)
        file_stats.append({
            "file": file_path.name,
            "chars": len(text),
            "chunks": len(chunks),
            "status": "ok",
        })

    if not all_chunks:
        print("\nERROR: No text extracted from any files", file=sys.stderr)
        sys.exit(1)

    # Generate embeddings
    print(f"\nGenerating embeddings for {len(all_chunks)} chunks...")
    embedded_chunks = embed_chunks(all_chunks, openai_client)

    # Upsert to Pinecone if configured
    if has_pinecone:
        print(f"\nUpserting to Pinecone...")
        upserted = upsert_to_pinecone(embedded_chunks)
        print(f"  Upserted {upserted} vectors")
    else:
        upserted = 0

    # Save chunk index as artifact (always — useful for debugging/verification)
    embeddings_path = output_dir / "chunks.jsonl"
    with open(embeddings_path, "w") as f:
        for chunk in embedded_chunks:
            record = {
                "id": chunk["id"],
                "text": chunk["text"],
                "metadata": chunk["metadata"],
                "embedding_dim": len(chunk["embedding"]),
            }
            f.write(json.dumps(record) + "\n")
    print(f"\nSaved chunk index to {embeddings_path}")

    # Write summary
    summary = {
        "files_processed": len(file_stats),
        "total_chunks": len(embedded_chunks),
        "total_chars": sum(s["chars"] for s in file_stats),
        "estimated_tokens": sum(s["chars"] for s in file_stats) // 4,
        "embedding_model": EMBEDDING_MODEL,
        "embedding_dimensions": len(embedded_chunks[0]["embedding"]) if embedded_chunks else 0,
        "pinecone_upserted": upserted,
        "pinecone_configured": has_pinecone,
        "files": file_stats,
    }

    summary_path = output_dir / "ingest_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"Saved summary to {summary_path}")

    # Print summary
    print(f"\n{'=' * 50}")
    print(f"RAG Ingest Complete")
    print(f"  Files: {summary['files_processed']}")
    print(f"  Chunks: {summary['total_chunks']}")
    print(f"  Est. tokens: {summary['estimated_tokens']:,}")
    if has_pinecone:
        print(f"  Pinecone: {upserted} vectors upserted")
    else:
        print(f"  Pinecone: not configured (file output only)")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
