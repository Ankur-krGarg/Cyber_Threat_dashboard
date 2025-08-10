import json, ijson
import logging
from pathlib import Path
from typing import List, Dict, Iterator, Optional
from collections import defaultdict
import gzip
from tqdm import tqdm

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Constants for text chunk validation
MAX_CHUNK_TEXT_LENGTH = 2048  # Max characters per chunk to prevent memory overload
MIN_TEXT_LENGTH = 10          # Minimum characters to treat a chunk as valid


class ChunkedThreatLoader:
    """
    Loader class for processing large chunked JSON threat data files.
    
    Capable of handling optionally gzipped files, this loader reconstructs full documents
    from text chunks grouped by 'record_id'. Handles malformed or inconsistent data gracefully.
    """

    def __init__(self, filepath: str):
        """
        Initialize the loader with a file path.

        Args:
            filepath (str): Path to the chunked JSON or .gz file.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"File {filepath} does not exist.")
        self.is_gzipped = self.filepath.suffix == ".gz"

    def _open_file(self):
        """
        Opens the file for reading, handling gzip if necessary.

        Returns:
            file object: File-like object for reading text lines.
        """
        if self.is_gzipped:
            return gzip.open(self.filepath, "rt", encoding="utf-8")
        return self.filepath.open("r", encoding="utf-8")

    def _stream_chunks(self) -> Iterator[Dict]:
        """
        Stream and yield chunk entries from the JSON file.

        Returns:
            Iterator[Dict]: Yields individual chunk dictionaries.

        Raises:
            JSONDecodeError: If file is not valid JSON.
        """
        with self._open_file() as f:
            #data = json.load(f)
            for chunk in ijson.items(f, "item"):
            #for chunk in data:
                yield chunk

    def load_and_reconstruct(self) -> List[Dict]:
        """
        Load and reconstruct full documents from individual text chunks.

        Chunks are grouped by 'record_id', sorted by 'chunk_index', and merged.

        Returns:
            List[Dict]: List of fully reconstructed threat documents.
        """
        records_map: Dict[int, Dict] = defaultdict(lambda: {
            "record_id": None,
            "source": None,
            "type": None,
            "indicator": None,
            "date": None,
            "text_chunks": []
        })

        logger.info(f"Start loading chunks from {self.filepath}...")

        total_chunks = 0
        valid_chunks = 0
        skipped_chunks = 0

        chunks_iter = self._stream_chunks()
        for chunk in tqdm(chunks_iter, desc="Loading chunks"):
            total_chunks += 1
            try:
                rec_id = int(chunk["record_id"])
                chunk_idx = int(chunk["chunk_index"])
                text = chunk.get("text", "")
                source = chunk.get("source", None)
                typ = chunk.get("type", None)
                indicator = chunk.get("indicator", None)
                date = chunk.get("date", None)

                # Skip empty or overlong text
                if not text or len(text) < MIN_TEXT_LENGTH:
                    logger.warning(f"Chunk text too short or missing — skipping record_id {rec_id} chunk {chunk_idx}")
                    skipped_chunks += 1
                    continue
                if len(text) > MAX_CHUNK_TEXT_LENGTH:
                    logger.warning(f"Chunk text too long (> {MAX_CHUNK_TEXT_LENGTH}) — skipping record_id {rec_id} chunk {chunk_idx}")
                    skipped_chunks += 1
                    continue

                rec_entry = records_map[rec_id]

                # Assign metadata once, validate on future chunks
                if rec_entry["record_id"] is None:
                    rec_entry.update({
                        "record_id": rec_id,
                        "source": source,
                        "type": typ,
                        "indicator": indicator,
                        "date": date
                    })
                else:
                    if (
                        rec_entry["source"] != source or
                        rec_entry["type"] != typ or
                        rec_entry["indicator"] != indicator or
                        rec_entry["date"] != date
                    ):
                        logger.warning(f"Inconsistent metadata in record_id {rec_id} chunk {chunk_idx}")

                # Append the chunk text and its index
                rec_entry["text_chunks"].append((chunk_idx, text))
                valid_chunks += 1

            except Exception as e:
                logger.error(f"Skipping malformed chunk: {chunk} — Error: {e}")
                skipped_chunks += 1

        logger.info(f"Processed {total_chunks} chunks: {valid_chunks} valid, {skipped_chunks} skipped.")

        # Reconstruct documents by sorting and joining text chunks
        full_documents = []
        for rec_id, rec in tqdm(records_map.items(), desc="Reconstructing documents"):
            try:
                rec["text_chunks"].sort(key=lambda x: x[0])
                full_text = " ".join(chunk[1] for chunk in rec["text_chunks"]).strip()
                document = {
                    "record_id": rec_id,
                    "source": rec["source"],
                    "type": rec["type"],
                    "indicator": rec["indicator"],
                    "date": rec["date"],
                    "text": full_text
                }
                full_documents.append(document)
            except Exception as e:
                logger.error(f"Failed to reconstruct record_id {rec_id}: {e}")

        logger.info(f"Loaded and reconstructed {len(full_documents)} full documents.")
        return full_documents


def ingest_data(filepath: str) -> List[Dict]:
    """
    High-level function to ingest and reconstruct documents from a file.

    Args:
        filepath (str): Path to the input JSON (.json or .json.gz) file.

    Returns:
        List[Dict]: List of fully reconstructed threat documents.
    """
    loader = ChunkedThreatLoader(filepath)
    return loader.load_and_reconstruct()
