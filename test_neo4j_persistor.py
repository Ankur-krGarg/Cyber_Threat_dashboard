from neo4j import GraphDatabase, Session
from neo4j.exceptions import TransientError
from typing import List
from test_schemas import ThreatEntity, ThreatRelationship

class Neo4jPersistor:
    def __init__(self, uri: str, user: str, password: str, run_id: str = str(None)):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.run_id = run_id
        self._ensure_indexes()

    def close(self):
        self.driver.close()

    def _run_with_retry(self, func, *args, max_retries=3, **kwargs):
        retries = 0
        while retries < max_retries:
            try:
                return func(*args, **kwargs)
            except TransientError as e:
                retries += 1
                if retries == max_retries:
                    raise

    def _ensure_indexes(self):
        with self.driver.session() as session:
            session.run("CREATE INDEX IF NOT EXISTS FOR (e:ThreatEntity) ON (e.name)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (r:RELATION) ON (r.type)")

    def save_entity(self, entity: ThreatEntity):
        if not entity.name or not entity.entity_type:
            raise ValueError("Entity must have a valid name and type")

        query = """
        MERGE (e:ThreatEntity {name: $name})
        SET e.entity_type = $entity_type,
            e.source_text = $source_text,
            e.confidence = $confidence,
            e.mitre_id = $mitre_id,
            e.description = $description,
            e.external_references = $external_references,
            e.run_id = $run_id
        """
        def run_query():
            with self.driver.session() as session:
                session.run(query, {
                    "name": entity.name,
                    "entity_type": entity.entity_type,
                    "source_text": entity.text,
                    "confidence": entity.confidence,
                    "mitre_id": entity.mitre_id,
                    "description": entity.description,
                    "external_references": entity.external_references or [],
                    "run_id": self.run_id
                })
        self._run_with_retry(run_query)

    def save_relationship(self, relation: ThreatRelationship):
        if not all([
            relation.source_name,
            relation.source_type,
            relation.target_name,
            relation.target_type,
            relation.relationship_type
        ]):
            raise ValueError("Relationship must have source/target name, type, and relationship_type")

        query = """
        MERGE (source:ThreatEntity {name: $source_name, entity_type: $source_type})
        MERGE (target:ThreatEntity {name: $target_name, entity_type: $target_type})
        MERGE (source)-[r:RELATION {type: $relationship_type}]->(target)
        SET r.description = $description,
            r.confidence = $confidence,
            r.run_id = $run_id
        """
        def run_query():
            with self.driver.session() as session:
                session.run(query, {
                    "source_name": relation.source_name,
                    "source_type": relation.source_type,
                    "target_name": relation.target_name,
                    "target_type": relation.target_type,
                    "relationship_type": relation.relationship_type,
                    "description": relation.description or "",
                    "confidence": relation.confidence or 0.0,
                    "run_id": self.run_id
                })
        self._run_with_retry(run_query)

    def save_entities_bulk(self, entities: List[ThreatEntity]):
        entities = [e for e in entities if e.name and e.entity_type]
        if not entities:
            return

        query = """
        UNWIND $entities AS entity
        MERGE (e:ThreatEntity {name: entity.name})
        SET e.entity_type = entity.entity_type,
            e.source_text = entity.source_text,
            e.confidence = entity.confidence,
            e.mitre_id = entity.mitre_id,
            e.description = entity.description,
            e.external_references = entity.external_references,
            e.run_id = $run_id
        """
        params = {
            "entities": [
                {
                    "name": e.name,
                    "entity_type": e.entity_type,
                    "source_text": e.text,
                    "confidence": e.confidence,
                    "mitre_id": e.mitre_id,
                    "description": e.description,
                    "external_references": e.external_references or []
                } for e in entities
            ],
            "run_id": self.run_id
        }
        def run_query():
            with self.driver.session() as session:
                session.run(query, params)
        self._run_with_retry(run_query)

    def clear_graph(self):
        def run_query():
            with self.driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
        self._run_with_retry(run_query)
