# src/embed_threat_chunks.py

import json
from tqdm import tqdm
import ollama

# Path to chunked threat data
CHUNKED_FILE = "processed/threats_chunked.json"
EMBEDDED_FILE = "processed/threats_embedded.json"

# Load chunked threat data
with open(CHUNKED_FILE, "r", encoding="utf-8") as f:
    chunks = json.load(f)

# Prepare text for embedding
def get_full_text(chunk):
    return (
        f"Source: {chunk.get('source', '')}\n"
        f"Type: {chunk.get('type', '')}\n"
        f"Indicator: {chunk.get('indicator', '')}\n"
        f"Text: {chunk.get('text', '')}"
    )

# Embedding each chunk
embedded_chunks = []
for i, chunk in enumerate(tqdm(chunks, desc="Embedding chunks")):
    full_text = get_full_text(chunk)

    try:
        response = ollama.embeddings(
            model="nomic-embed-text:v1.5",
            prompt=full_text
        )
        embedding = response["embedding"]
    except Exception as e:
        print(f"[Error] Failed at chunk {i}: {e}")
        continue

    embedded_chunks.append({
        "id": i,
        "source": chunk.get("source"),
        "type": chunk.get("type"),
        "indicator": chunk.get("indicator"),
        "text": chunk.get("text"),
        "embedding": embedding
    })

# Save the embedded data
with open(EMBEDDED_FILE, "w", encoding="utf-8") as f:
    json.dump(embedded_chunks, f, indent=2)

print(f"\n✅ Embedding complete. Total embedded chunks: {len(embedded_chunks)}")
