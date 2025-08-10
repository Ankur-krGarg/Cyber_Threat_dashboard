#import sys
import os
import time, datetime
from tqdm import tqdm  # progress bar with ETA
from pathlib import Path
import logging
from typing import List, Tuple, Set, Sequence
import json
import functools
import argparse
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Add parent directory of ai_agents (which is Threat_dashboard) to sys.path
#sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from test_schemas import ThreatEntity, ThreatRelationship, EntityType
from test_ner_extractor import perform_hybrid_ner
from test_relation_extractor import extract_relationships_llm
from test_mitre_stix_integrator import enrich_entities_with_mitre_stix
from test_neo4j_persistor import Neo4jPersistor
from test_ingestion import ingest_data


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CHECKPOINT_FILE = Path("processed_records.json")

metrics = {
    'empty_texts': 0,
    'total_entities': 0,
    'total_relationships': 0,
    'malformed_docs': 0
}

def timeit(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"Step {func.__name__} took {elapsed:.2f}s")
        return result
    return wrapper

def load_checkpoint() -> Set[int]:
    if CHECKPOINT_FILE.exists():
        with CHECKPOINT_FILE.open("r") as f:
            processed = set(json.load(f))
            logger.info(f"Loaded checkpoint with {len(processed)} processed records.")
            return processed
    return set()

def save_checkpoint(processed_ids: Set[int]):
    with CHECKPOINT_FILE.open("w") as f:
        json.dump(list(processed_ids), f)
    logger.debug(f"Saved checkpoint with {len(processed_ids)} processed records.")

@timeit
def process_document(doc: dict) -> Tuple[List[ThreatEntity], List[ThreatRelationship]]:
    """
    Processes a single document through the full KG pipeline:
    - NER → MITRE Enrichment → Relationship Extraction
    """
    text = doc.get("text", "")
    if not text.strip():
        logger.warning(f"Empty text found in record_id: {doc.get('record_id')}")
        metrics['empty_texts'] += 1
        return [], []

    try:
        logger.info(f"Performing NER for record_id {doc.get('record_id')}")
        entities = perform_hybrid_ner(text)
        metrics['total_entities'] += len(entities)

        logger.info(f"Enriching entities with MITRE ATT&CK for record_id {doc.get('record_id')}")
        enriched_entities = enrich_entities_with_mitre_stix(entities)

        logger.info(f"Extracting relationships for record_id {doc.get('record_id')}")
        relationships = extract_relationships_llm(text, enriched_entities, groq_key=GROQ_API_KEY)
        #relationships = extract_relationships_llm(text, enriched_entities)
        metrics['total_relationships'] += len(relationships)

        return enriched_entities, relationships
    except Exception as e:
        logger.error(f"Error processing record_id {doc.get('record_id')}: {e}")
        metrics['malformed_docs'] += 1
        return [], []

def ingest_to_neo4j(entities: List[ThreatEntity], relationships: List[ThreatRelationship], db: Neo4jPersistor, dry_run: bool = False):
    """
    Persists extracted entities and relationships to the Neo4j database.
    """
    if dry_run:
        logger.info(f"Dry-run mode: would save {len(entities)} entities and {len(relationships)} relationships.")
        return

    for entity in entities:
        try:
            db.save_entity(entity)
        except Exception as e:
            logger.error(f"Failed to persist entity {entity.name}: {e}")

    for relation in relationships:
        try:
            db.save_relationship(relation)
        except Exception as e:
            logger.error(f"Failed to persist relationship: {relation}: {e}")

def run_pipeline(chunked_json_path: str, neo4j_uri: str, neo4j_user: str, neo4j_password: str, dry_run: bool = False):
    """
    Full pipeline execution:
    - Load chunked JSON
    - Process each document
    - Persist results to Neo4j (or dry-run)
    """
    logger.info(f"Loading documents from {chunked_json_path}")
    documents = ingest_data(chunked_json_path)
    
    import random
    documents = random.sample(documents, min(3, len(documents)))  

    total_docs = len(documents)
    logger.info(f"{total_docs} documents loaded.")

    if total_docs == 0:
        logger.warning("No documents found to process. Exiting pipeline.")
        return

    processed_ids = load_checkpoint()

    # Generate a run_id once here, pass to Neo4jPersistor
    run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    db = Neo4jPersistor(uri=neo4j_uri, user=neo4j_user, password=neo4j_password, run_id=run_id)

    try:
        # Estimate total time by timing a sample first (optional)
        sample_size = min(3, total_docs)
        if sample_size > 0:
            logger.info(f"Estimating total time by processing sample of {sample_size} documents...")
            start_sample = time.time()
            for i in range(sample_size):
                process_document(documents[i])
            end_sample = time.time()
            avg_per_doc = (end_sample - start_sample) / sample_size
            estimated_total = avg_per_doc * total_docs
            logger.info(f"Estimated total processing time: {estimated_total:.2f} seconds (~{estimated_total/60:.2f} minutes)")

        # Process full dataset with progress bar and checkpointing
        for i, doc in enumerate(tqdm(documents, desc="Processing documents")):
            record_id = doc.get("record_id")
            if record_id is None:
                logger.warning("Skipping document without a record_id")
                continue
            if record_id in processed_ids:
                logger.info(f"Skipping already processed record_id {record_id}")
                continue
            try:
                entities, relationships = process_document(doc)
                ingest_to_neo4j(entities, relationships, db, dry_run=dry_run)
                processed_ids.add(record_id)
                save_checkpoint(processed_ids)
            except Exception as e:
                logger.error(f"Processing failed for record_id {record_id}: {e}")

    finally:
        db.close()
        logger.info("Neo4j connection closed.")

    logger.info(f"Metrics summary: {metrics}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence KG Pipeline")
    parser.add_argument("--dry-run", action="store_true", help="Run pipeline without saving to DB")
    args = parser.parse_args()

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    CHUNKED_JSON_PATH = os.getenv("CHUNKED_JSON_PATH", r"./processed/threats_chunked_clean.json")
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "testpassword")

    logger.info(f"Pipeline started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    start_time = time.time()
    run_pipeline(CHUNKED_JSON_PATH, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, dry_run=args.dry_run)
    end_time = time.time()

    elapsed = end_time - start_time
    logger.info(f"Total pipeline execution time: {elapsed:.2f} seconds (~{elapsed/60:.2f} minutes)")
