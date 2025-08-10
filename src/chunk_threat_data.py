import json
from bs4 import BeautifulSoup
from langchain.text_splitter import RecursiveCharacterTextSplitter
import re

def clean_html(raw_html):
    """Enhanced HTML cleaning with JSON artifact removal"""
    if not raw_html or not isinstance(raw_html, str):
        return ""
    
    # First parse HTML
    soup = BeautifulSoup(raw_html, "html.parser")
    text = soup.get_text(separator="\n", strip=True)
    
    # Remove common JSON artifacts
    text = re.sub(r"['\"{}:]+", " ", text)  # Remove JSON syntax
    text = re.sub(r"\b\w+[A-Z]\w+\b", "", text)  # Remove camelCase words
    text = re.sub(r"\s+", " ", text)  # Normalize whitespace
    
    return text.strip()

def chunk_threat_data(input_path, output_path, chunk_size=1000, chunk_overlap=200):
    """Enhanced chunking with better text preservation"""
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", r"\.\s+", r"!\s+", r"\?\s+", r",\s+", " ", ""]  # Better sentence splitting
    )
    
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_chunks = []
    skipped_count = 0

    print(f"Total records to process: {len(data)}")

    for record_id, item in enumerate(data):
        raw_desc = item.get("description", "")
        cleaned_text = clean_html(raw_desc)

        if not cleaned_text.strip():
            skipped_count += 1
            print(f"Skipping record {record_id} due to empty description.")
            continue

        chunks = text_splitter.split_text(cleaned_text)

        for chunk_idx, chunk_text in enumerate(chunks):
            if len(chunk_text.strip()) < 50:
                continue
                
            # Preserve cybersecurity indicators
            chunk_text = re.sub(
                r"(CVE-\d+-\d+)", 
                r"VULNERABILITY_\1",  # Mark CVEs for easy identification
                chunk_text
            )
            
            all_chunks.append({
                "record_id": record_id,
                "chunk_index": chunk_idx,
                "source": item.get("source", ""),
                "type": item.get("type", ""),
                "indicator": item.get("indicator", ""),
                "date": item.get("date", ""),
                "text": chunk_text.strip()
            })

        if record_id % 10 == 0:
            print(f"Processed {record_id} records, total chunks so far: {len(all_chunks)}")

    print(f"Finished processing. Total chunks created: {len(all_chunks)}")
    print(f"Total records skipped due to empty description: {skipped_count}")

    with open(output_path, "w", encoding="utf-8") as fout:
        json.dump(all_chunks, fout, indent=2, ensure_ascii=False)  # Preserve non-ASCII chars

if __name__ == "__main__":
    chunk_threat_data(
        input_path="processed/threats.json",
        output_path="processed/threats_chunked_clean.json",  # New output name
        chunk_size=1000,
        chunk_overlap=200
    )
