# retriever_agent.py

import argparse
from cohere import Client as CohereClient
from neo4j import GraphDatabase
from dotenv import load_dotenv
import os

load_dotenv()

class RetrieverAgent:
    """
    Retriever Agent:
    - Converts user query into embeddings using Cohere
    - Searches local mock vector DB (simulating DeepLake)
    - Falls back to keyword search if needed
    - Validates results with Neo4j knowledge graph
    """

    def __init__(self, cohere_api_key, neo4j_uri, neo4j_user, neo4j_password):
        self.cohere = CohereClient(cohere_api_key)
        self.neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.vector_db = self.MockVectorDB()
        self.embedding_store = {}  # Store embeddings for queries if needed

    def embed_query(self, query):
        """Convert query text to embedding vector using Cohere."""
        response = self.cohere.embed(texts=[query])
        embedding = response.embeddings[0]
        self.embedding_store[query] = embedding  # Store embedding internally
        return embedding
    
    def search_vector_db(self, embedding, top_k=5):
        """Search mock vector DB with embedding, return top_k results."""
        return self.vector_db.search(embedding, top_k)

    def keyword_search(self, query):
        """Fallback keyword search in mock data."""
        return self.vector_db.keyword_search(query)

    def validate_with_neo4j(self, node_ids):
        """Validate node IDs by fetching node details from Neo4j."""
        with self.neo4j_driver.session() as session:
            results = session.run(
                "MATCH (n) WHERE elementId(n) IN $ids RETURN elementId(n) AS id, n.name AS name LIMIT $limit",
                #"MATCH (n) WHERE n.id IN $ids RETURN n.id AS id, n.name AS name LIMIT $limit",
                ids=node_ids, limit=len(node_ids)
            )
            return [record.data() for record in results]

    def retrieve(self, query):
        """Full retrieval pipeline: embed, search, fallback, validate."""
        embedding = self.embed_query(query)
        results = self.search_vector_db(embedding)

        if not results:
            results = self.keyword_search(query)

        node_ids = [r['id'] for r in results]
        validated_nodes = self.validate_with_neo4j(node_ids)
        return validated_nodes

    class MockVectorDB:
        """Local mock vector DB simulating DeepLake behavior."""

        def __init__(self):
            self.data = [
            {
                "id": "4:eacf5e48-1f62-47e7-9d83-722559328bfd:514",  # Iranian cyber actors
                "content": "Phishing campaign targeting banks"
            },
            {
                "id": "4:eacf5e48-1f62-47e7-9d83-722559328bfd:515",  # healthcare sector
                "content": "Finance sector phishing attempts"
            },
            {
                "id": "4:eacf5e48-1f62-47e7-9d83-722559328bfd:516",  # Replace with another valid ID
                "content": "Ransomware attacks on healthcare"
            },
        ]

        def search(self, embedding, top_k):
            """Mock search returns top_k items."""
            return self.data[:top_k]

        def keyword_search(self, query):
            """Simple keyword search in mock data."""
            query_words = query.lower().split()
            return [item for item in self.data if any(word in item["content"].lower() for word in query_words)]

def main():
    parser = argparse.ArgumentParser(description="Retriever Agent CLI")
    parser.add_argument("--cohere_key", type=str, default=os.getenv("COHERE_API_KEY"), help="Cohere API key")
    parser.add_argument("--neo4j_password", type=str, default=os.getenv("NEO4J_PASSWORD"), help="Neo4j password")
    parser.add_argument("--query", type=str, required=True, help="User query text to search")
    parser.add_argument("--neo4j_uri", type=str, default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j_user", type=str, default=os.getenv("NEO4J_USER", "neo4j"), help="Neo4j username")
    
    args = parser.parse_args()

    retriever = RetrieverAgent(
        cohere_api_key=args.cohere_key,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password
    )
    
    results = retriever.retrieve(args.query)
    print("Retrieved Nodes:")
    for node in results:
        print(f"- ID: {node['id']}, Name: {node.get('name', 'N/A')}")

if __name__ == "__main__":
    main()
