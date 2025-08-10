from typing import List, Optional
from test_schemas import ThreatEntity
import logging
import os
import json
import requests
from cachetools import TTLCache, cached
from pathlib import Path

# Initialize logger
logger = logging.getLogger(__name__)

# Memory cache: max 1000 entries, TTL = 3600 seconds (1 hour)
mitre_cache = TTLCache(maxsize=1000, ttl=3600)

# Path to local MITRE data cache
LOCAL_CACHE_PATH = r"D:\Tiny_threat_dashboard\processed\mitre_attack_cache.json"

# Optional: MITRE TAXII API (if dynamic fetching is added later)
MITRE_STIX_API_URL = (
    "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/objects"
)


def load_local_cache() -> Optional[dict]:
    """
    Loads MITRE ATT&CK data from a local JSON cache file.

    Returns:
        dict: Parsed JSON data if file exists and is valid, else None.
    """
    if os.path.exists(LOCAL_CACHE_PATH):
        try:
            with open(LOCAL_CACHE_PATH, "r", encoding="utf-8") as f:
                logger.info("Loaded MITRE cache from local file.")
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load local MITRE cache: {e}")
    return None


def save_local_cache(data: dict):
    """
    Saves MITRE ATT&CK data to a local JSON file.

    Args:
        data (dict): Parsed MITRE data to cache.
    """
    try:
        with open(LOCAL_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved MITRE data to local cache.")
    except Exception as e:
        logger.warning(f"Failed to save MITRE cache: {e}")


@cached(mitre_cache)
def fetch_mitre_data() -> dict:
    """
    Fetches MITRE data from local cache, or raises if unavailable.

    Returns:
        dict: MITRE STIX data.

    Raises:
        FileNotFoundError: If local cache is missing.
    """
    local_data = load_local_cache()
    if local_data:
        return local_data
    error_msg = f"No local MITRE ATT&CK cache found at '{LOCAL_CACHE_PATH}'. Cannot proceed without MITRE data."
    logger.critical(error_msg)
    raise FileNotFoundError(error_msg)


def find_mitre_info(name: str, mitre_data: dict) -> Optional[dict]:
    """
    Finds MITRE info for a given entity name by matching ID or name.

    Args:
        name (str): Entity name or MITRE ID.
        mitre_data (dict): MITRE data to search.

    Returns:
        dict: MITRE enrichment details if found, else None.
    """
    if not mitre_data or "objects" not in mitre_data:
        return None

    name_upper = name.upper()
    for obj in mitre_data["objects"]:
        ext_refs = obj.get("external_references", [])
        mitre_id = next(
            (ref.get("external_id") for ref in ext_refs if ref.get("source_name") == "mitre-attack"),
            None
        )

        if mitre_id and mitre_id.upper() == name_upper:
            return {
                "mitre_id": mitre_id,
                "description": obj.get("description", ""),
                "external_references": [ref.get("url") for ref in ext_refs if ref.get("url")],
                "type": obj.get("type", ""),
                "name": obj.get("name", "")
            }

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
    Enriches a list of ThreatEntity objects with MITRE STIX data.

    Args:
        entities (List[ThreatEntity]): List of threat entities to enrich.

    Returns:
        List[ThreatEntity]: Updated list with enriched MITRE fields (if applicable).
    """
    try:
        mitre_data = fetch_mitre_data()
    except FileNotFoundError:
        logger.error("MITRE enrichment skipped due to missing local cache.")
        return entities

    enriched_entities = []

    for entity in entities:
        if entity.entity_type.lower() in {"ttp", "technique", "tactic"}:
            mitre_info = find_mitre_info(entity.name, mitre_data)
            if mitre_info:
                entity.mitre_id = mitre_info.get("mitre_id", entity.mitre_id)
                entity.description = mitre_info.get("description", entity.description)
                entity.external_references = mitre_info.get("external_references", entity.external_references or [])
                logger.debug(
                    f"Enriched entity '{entity.name}' with MITRE ID '{entity.mitre_id}' and type '{mitre_info.get('type')}'."
                )
            else:
                logger.debug(f"No MITRE enrichment found for entity '{entity.name}'.")
        enriched_entities.append(entity)

    return enriched_entities
