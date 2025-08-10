"""
Relationship extractor using Groq LLM.
Maintains original function signatures while adding API support and fallback.
"""

import json
import logging
import time
import re
from typing import List, Optional, Dict, Sequence
from openai import OpenAI
from groq import Groq
from test_schemas import ThreatEntity, ThreatRelationship
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

logger = logging.getLogger(__name__)


def extract_json_array(text: str) -> Optional[List[Dict]]:
    """Extract JSON array from text containing extra text around it."""
    try:
        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            json_str = match.group(0)
            return json.loads(json_str)
    except Exception as e:
        logger.error(f"Failed to extract JSON array: {e}")
    return None


class BaseLLMClient:
    """Base class for shared LLM logic."""

    def __init__(self, model: str = "", temperature: float = 0.3):
        self.model = model
        self.temperature = temperature

    def extract_relations(
        self,
        text: str,
        entities: List[Dict],
        max_retries: int = 2
    ) -> Optional[List[Dict]]:
        prompt = self._build_prompt(text, entities)
        for attempt in range(1, max_retries + 1):
            try:
                response_text = self._call_api(prompt)
                if not response_text:
                    logger.warning(f"{self.__class__.__name__} empty response on attempt {attempt}.")
                    continue
                relations = extract_json_array(response_text)
                if relations is None:
                    logger.error("Failed to parse JSON array from response.")
                    logger.debug(f"Raw output:\n{response_text}")
                    continue
                return relations
            except Exception as e:
                logger.error(f"{self.__class__.__name__} API request failed: {e}")
                if attempt < max_retries:
                    time.sleep(1)
        return None

    def _build_prompt(self, text: str, entities: List[Dict]) -> str:
        entity_list = "\n".join(f"- {e['name']} ({e['type']})" for e in entities)
        return (
            f"Extract cybersecurity relationships from the following text.\n\n"
            f"Text:\n{text}\n\n"
            f"Entities:\n{entity_list}\n\n"
            f"Return a JSON array of relation objects. Each object must have:\n"
            f"- source_name (string)\n- source_type (string)\n"
            f"- target_name (string)\n- target_type (string)\n"
            f"- relationship_type (exploits, targets, uses, variant_of)\n"
            f"- confidence (float between 0 and 1)\n"
            f"- description (max 50 words)\n\n"
            f"Output only valid JSON array.\nBegin extraction now."
        )

    def _call_api(self, prompt: str) -> Optional[str]:
        raise NotImplementedError("Must be implemented by subclass.")


class GroqClient(BaseLLMClient):
    """Handles Groq API communication"""

    def __init__(self, api_key: Optional[str] = None, model: str = "llama-3.3-70b-versatile", temperature: float = 0.3):
        super().__init__(model, temperature)
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=self.api_key)

    def _call_api(self, prompt: str) -> Optional[str]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
            max_tokens=1024
        )
        logger.debug(f"Groq raw response: {response}")
        return response.choices[0].message.content

class LocalLlamaClient(BaseLLMClient):
    """Local LLaMA client using LM Studio's OpenAI-compatible API."""

    def __init__(self, base_url: str = "http://192.168.31.1:1229/v1", model: str = "meta-llama-3.1-8b-instruct", temperature: float = 0.3):
        super().__init__(model, temperature)
        self.client = OpenAI(
        base_url = base_url,
        api_key = "lm-studio"  # Required dummy key for LM Studio
        )

    def _call_api(self, prompt: str) -> Optional[str]:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Local LLaMA call failed: {e}")
            return None

def extract_relationships_llm(
    text: str,
    entities: List[ThreatEntity],
    groq_key: Optional[str] = None,
    fallback_to_local: bool = True
) -> List[ThreatRelationship]:
    """Relationship extraction using Groq with optional fallback."""

    if not text or not entities:
        logger.warning("Empty input received for relationship extraction.")
        return []

    # Defensive extraction of name and type from entities
    entity_dicts = [{"name": getattr(e, "name", None), "type": getattr(e, "type", None)} for e in entities]
    entity_dicts = [e for e in entity_dicts if e["name"] and e["type"]]

    def parse_relations(relations: List[Dict]) -> List[ThreatRelationship]:
        cleaned = []
        for r in relations:
            if all(k in r for k in ("source_name", "source_type", "target_name", "target_type", "relationship_type")):
                cleaned.append(
                    ThreatRelationship(
                        source_name=r["source_name"],
                        source_type=r["source_type"],
                        target_name=r["target_name"],
                        target_type=r["target_type"],
                        relationship_type=r["relationship_type"],
                        confidence=r.get("confidence", 0.7),
                        description=r.get("description", "")
                    )
                )
            else:
                logger.warning(f"Incomplete relation data skipped: {r}")
        return cleaned

    # Try Groq extraction
    key = groq_key or api_key
    if key:
        logger.info("Attempting extraction with Groq LLM...")
        relations = GroqClient(api_key=key).extract_relations(text, entity_dicts)
        if relations:
            logger.info(f"Groq succeeded with {len(relations)} relationships.")
            return parse_relations(relations)
        else:
            logger.warning("Groq extraction returned no valid relations.")

    # Fallback local 
    if fallback_to_local:
        logger.info("Trying local LLaMA fallback via LM Studio...")
        try:
            relations = LocalLlamaClient().extract_relations(text, entity_dicts)
        except Exception as e:
            logger.warning(f"Local LLM failed, skipping: {e}")  # ✅ Fails gracefully
        return []
        
    return []

