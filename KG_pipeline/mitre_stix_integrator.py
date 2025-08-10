from typing import List, Optional
from .schemas import ThreatEntity
import logging
import os
import json
import requests
from cachetools import TTLCache, cached
from pathlib import Path

logger = logging.getLogger(__name__)

# Cache to store MITRE data in-memory for 1 hour (3600 seconds), max 1000 entries
mitre_cache = TTLCache(maxsize=1000, ttl=3600)

# Local cache file path to persist MITRE data between runs
LOCAL_CACHE_PATH = r"D:\Tiny_threat_dashboard\processed\mitre_attack_cache.json"

# MITRE ATT&CK TAXII API or equivalent URL to fetch STIX data (replace with actual URL if needed)
MITRE_STIX_API_URL = "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/objects"

def load_local_cache() -> Optional[dict]:
    """Load cached MITRE data from local file if exists."""
    if os.path.exists(LOCAL_CACHE_PATH):
        try:
            with open(LOCAL_CACHE_PATH, "r", encoding="utf-8") as f:
                logger.info("Loaded MITRE cache from local file.")
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load local MITRE cache: {e}")
    return None

def save_local_cache(data: dict):
    """Save MITRE data to local cache file."""
    try:
        with open(LOCAL_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info("Saved MITRE data to local cache file.")
    except Exception as e:
        logger.warning(f"Failed to save MITRE cache: {e}")

@cached(mitre_cache)
def fetch_mitre_data() -> dict:
    """
    Fetch MITRE ATT&CK STIX objects from TAXII API endpoint.
    Caches results in-memory and also saves to local cache file.
    """
    local_data = load_local_cache()
    if local_data:
        return local_data
    else:
        # If no local cache, clearly indicate that data is missing
        error_msg = f"No local MITRE ATT&CK cache found at '{LOCAL_CACHE_PATH}'. Cannot proceed without MITRE data."
        logger.critical(error_msg)
        raise FileNotFoundError(error_msg) # Raise an error if no local cache is found
        
def find_mitre_info(name: str, mitre_data: dict) -> Optional[dict]:
    """
    Lookup MITRE technique or tactic info by name or ID from loaded STIX data.
    Name matching logic can be adapted as needed.
    """
    if not mitre_data or "objects" not in mitre_data:
        return None

    name_upper = name.upper()
    for obj in mitre_data["objects"]:
        # Example: match on 'external_references' or 'name' fields
        ext_refs = obj.get("external_references", [])
        mitre_id = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
        if mitre_id and mitre_id.upper() == name_upper:
            return {
                "mitre_id": mitre_id,
                "description": obj.get("description", ""),
                "external_references": [ref.get("url") for ref in ext_refs if ref.get("url")],
                "type": obj.get("type", ""),
                "name": obj.get("name", "")
            }
        # Also match by name string (case insensitive)
        if obj.get("name", "").upper() == name_upper:
            return {
                "mitre_id": mitre_id or "",
                "description": obj.get("description", ""),
                "external_references": [ref.get("url") for ref in ext_refs if ref.get("url")],
                "type": obj.get("type", ""),
                "name": obj.get("name", "")
            }
    return None

def enrich_entities_with_mitre_stix(entities: List[ThreatEntity]) -> List[ThreatEntity]:
    """
    Enrich ThreatEntity list with MITRE ATT&CK data if applicable.
    Supports TTP, technique, tactic types.
    Falls back gracefully if MITRE data not available.
    """
    mitre_data = fetch_mitre_data()
    enriched_entities = []

    for entity in entities:
        if entity.type.lower() in {"ttp", "technique", "tactic"}:
            mitre_info = find_mitre_info(entity.name, mitre_data)
            if mitre_info:
                entity.mitre_id = mitre_info.get("mitre_id", entity.mitre_id)
                entity.description = mitre_info.get("description", entity.description)
                entity.external_references = mitre_info.get("external_references", entity.external_references or [])
                logger.debug(f"Enriched entity '{entity.name}' with MITRE ID '{entity.mitre_id}' and type '{mitre_info.get('type')}'.")
            else:
                logger.debug(f"No MITRE enrichment found for entity '{entity.name}'.")
        enriched_entities.append(entity)

    return enriched_entities
