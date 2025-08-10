import json, ijson
import logging
from pathlib import Path
from typing import List, Dict, Iterator, Optional
from collections import defaultdict
import gzip
from tqdm import tqdm

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

MAX_CHUNK_TEXT_LENGTH = 2048  # max chars per chunk to avoid huge memory spikes
MIN_TEXT_LENGTH = 10              # minimum valid text length for a chunk

class ChunkedThreatLoader:
    """
    Loader for chunked threat JSON data files.
    Efficiently loads large chunked JSON file (optionally compressed),
    reconstructs full documents by record_id, sorts chunks by chunk_index,
    and yields combined documents.
    Handles incomplete or malformed chunks by logging and skipping.
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"File {filepath} does not exist.")
        self.is_gzipped = self.filepath.suffix == ".gz"

    def _open_file(self):
        if self.is_gzipped:
            return gzip.open(self.filepath, "rt", encoding="utf-8")
        else:
            return self.filepath.open("r", encoding="utf-8")

    def _stream_chunks(self) -> Iterator[Dict]:
        """
        Generator that yields chunks one by one from the large JSON file.
        Assumes the file is a JSON array of objects.
        Uses streaming parsing to handle very large files.
        """
        with self._open_file() as f:
            # Load entire array - consider streaming libs if file is huge
            data = json.load(f)
            for chunk in data:
                yield chunk

    def load_and_reconstruct(self) -> List[Dict]:
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

        # Optionally, you could use ijson or similar streaming JSON parser for huge files

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

                # Data quality checks
                if not (text and len(text) >= MIN_TEXT_LENGTH):
                    logger.warning(f"Chunk text too short or missing, skipping record_id {rec_id} chunk {chunk_idx}")
                    skipped_chunks += 1
                    continue
                if len(text) > MAX_CHUNK_TEXT_LENGTH:
                    logger.warning(f"Chunk text too long (>{MAX_CHUNK_TEXT_LENGTH}), skipping record_id {rec_id} chunk {chunk_idx}")
                    skipped_chunks += 1
                    continue

                rec_entry = records_map[rec_id]
                # Set metadata only once or validate consistency
                if rec_entry["record_id"] is None:
                    rec_entry["record_id"] = rec_id
                    rec_entry["source"] = source
                    rec_entry["type"] = typ
                    rec_entry["indicator"] = indicator
                    rec_entry["date"] = date
                else:
                    if (rec_entry["source"] != source or rec_entry["type"] != typ or
                        rec_entry["indicator"] != indicator or rec_entry["date"] != date):
                        logger.warning(f"Inconsistent metadata in record_id {rec_id} chunk {chunk_idx}")

                # Append chunk text with chunk index for sorting later
                rec_entry["text_chunks"].append((chunk_idx, text))
                valid_chunks += 1

            except Exception as e:
                logger.error(f"Skipping malformed chunk: {chunk} Error: {e}")
                skipped_chunks += 1

        logger.info(f"Processed {total_chunks} chunks: {valid_chunks} valid, {skipped_chunks} skipped.")

        # Reconstruct full text by concatenating chunks sorted by chunk_index
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
                logger.error(f"Failed reconstructing record_id {rec_id}: {e}")

        logger.info(f"Loaded and reconstructed {len(full_documents)} full documents.")
        return full_documents


def ingest_data(filepath: str) -> List[Dict]:
    """
    Top-level function to ingest chunked threat data from the given JSON file path.

    Args:
        filepath (str): Path to the chunked JSON file (.json or .json.gz).

    Returns:
        List[Dict]: List of reconstructed full threat documents.
    """
    loader = ChunkedThreatLoader(filepath)
    return loader.load_and_reconstruct()
