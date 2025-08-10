import os
import json
import argparse
from cohere import Client as CohereClient
from dotenv import load_dotenv

load_dotenv()

class EnhancerAgent:
    """
    Enhancer Agent:
    - Takes node info (id, name, entity_type)
    - Uses LLM to generate enriched details (summary, risk level, tags)
    """

    def __init__(self, cohere_api_key):
        self.cohere = CohereClient(cohere_api_key)

    def enrich_node(self, node):
        """Enriches a single node using a prompt and LLM."""
        prompt = (
            f"Enrich the following cybersecurity entity with a brief summary, risk level "
            f"(Low/Medium/High), and 3 tags:\n\n"
            f"Name: {node['name']}\n"
            f"Entity Type: {node['entity_type']}\n\n"
            f"Return JSON with keys: id, name, entity_type, summary, risk_level, tags"
        )

        try:
            response = self.cohere.generate(prompt=prompt, max_tokens=300)
            output_text = response.generations[0].text.strip()

            # Handle multi-JSON or extra data errors
            enriched_node = self.safe_parse_json(output_text)
            enriched_node["id"] = node.get("id", "N/A")
            enriched_node["name"] = node["name"]
            enriched_node["entity_type"] = node["entity_type"]
            return enriched_node

        except Exception as e:
            return {
                "id": node.get("id", "N/A"),
                "name": node["name"],
                "entity_type": node["entity_type"],
                "summary": "N/A",
                "risk_level": "Unknown",
                "tags": [],
                "error": str(e),
            }

    @staticmethod
    def safe_parse_json(text):
        """Try to parse the first valid JSON object from the text."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract the first JSON object manually
            for line in text.strip().split('\n'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            raise ValueError("No valid JSON found in response.")

def main():
    parser = argparse.ArgumentParser(description="Enhancer Agent CLI")
    parser.add_argument("--cohere_key", type=str, default=os.getenv("COHERE_API_KEY"), help="Cohere API Key")
    args = parser.parse_args()

    # Example mock input
    input_nodes = [
        {"id": "node1", "name": "Iranian cyber actors", "entity_type": "threat actor"},
        {"id": "node2", "name": "healthcare sector", "entity_type": "industry"},
    ]

    agent = EnhancerAgent(cohere_api_key=args.cohere_key)
    print("Enriched Nodes:")

    for node in input_nodes:
        enriched = agent.enrich_node(node)
        print(json.dumps(enriched, indent=2))

if __name__ == "__main__":
    main()
