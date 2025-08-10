# src/parser_logic.py

import os
import json
import xmltodict
import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Union

# Setup logging once
logging.basicConfig(
    filename='parser.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

REQUIRED_FIELDS = ["source", "type", "indicator", "description", "date"]
FALLBACK_DIR = Path(__file__).resolve().parent.parent / "fallback"
FALLBACK_DIR.mkdir(exist_ok=True)

def save_fallback(data, source_file, reason="parse_error"):
    fallback_path = FALLBACK_DIR / f"{source_file}_{reason}.json"
    try:
        with open(fallback_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logging.warning(f"Saved fallback data to {fallback_path}")
    except Exception as e:
        logging.error(f"Failed to write fallback file: {e}")

def normalize_data(raw_data: Union[dict, list, str], source_name: str) -> List[Dict[str, str]]:
    normalized = []

    # Debug: print type of raw_data
    logging.info(f"Normalizing data from source: {source_name}, type: {type(raw_data)}")

    # If raw_data is a dict and has RSS structure, unpack items
    if isinstance(raw_data, dict):
        if 'rss' in raw_data:
            channel = raw_data['rss'].get('channel', {})
            items = channel.get('item', [])
            # Ensure items is a list
            if isinstance(items, dict):
                items = [items]
            raw_data = items
            logging.info(f"Unpacked {len(items)} RSS items from source: {source_name}")
        else:
            # Wrap dict in a list for uniform processing
            raw_data = [raw_data]
    elif isinstance(raw_data, str):
        # Split text lines into list
        raw_data = raw_data.strip().splitlines()

    for item in raw_data:
        try:
            if isinstance(item, dict):
                # Extract indicator and description with fallbacks
                indicator = item.get("indicator") or item.get("id") or item.get("cve_id") or item.get("title") or "unknown"
                description = item.get("description") or item.get("desc") or item.get("summary") or str(item)
                raw = item  # Save full item dict in raw

            else:
                indicator = str(item)
                description = "Extracted plain text line"
                raw = {"text": item}

            normalized.append({
                "source": source_name,
                "type": "threat",
                "indicator": indicator,
                "description": description,
                "date": pd.Timestamp.now().isoformat(),
                "raw": raw
            })
        except Exception as e:
            logging.warning(f"Failed to normalize item in {source_name}: {e}")

    return normalized

# Rest of the file remains exactly the same (parse_json, parse_xml, parse_txt functions)
def parse_json(file_path: Path) -> List[Dict]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return normalize_data(data, file_path.stem)
    except Exception as e:
        logging.error(f"JSON Parse Error {file_path.name}: {e}")
        save_fallback({"file": str(file_path), "error": str(e)}, file_path.stem, reason="json_error")
        return []


def parse_xml(file_path: Path) -> List[Dict]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = xmltodict.parse(f.read())
        return normalize_data(data, file_path.stem)
    except Exception as e:
        logging.error(f"XML Parse Error {file_path.name}: {e}")
        save_fallback({"file": str(file_path), "error": str(e)}, file_path.stem, reason="xml_error")
        return []


def parse_txt(file_path: Path) -> List[Dict]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return normalize_data(lines, file_path.stem)
    except Exception as e:
        logging.error(f"TXT Parse Error {file_path.name}: {e}")
        save_fallback({"file": str(file_path), "error": str(e)}, file_path.stem, reason="txt_error")
        return []
