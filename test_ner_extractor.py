from transformers.pipelines import pipeline
from typing import List, Optional, Set, Tuple
from test_schemas import ThreatEntity, map_entity_label, EntityType
import re

NOISY_TOKENS = {"run", "the", ".", ",", "e", "dll32.exe", "rund1132.exe"}

def filter_and_deduplicate_entities(
    entities: List[ThreatEntity],
    min_confidence: float = 0.7,
    exclude_short_names: bool = True,
) -> List[ThreatEntity]:
    """
    Filters and deduplicates a list of ThreatEntity objects by confidence and noisy tokens.
    """
    seen = {}  # (entity_name_lower, entity_type) -> ThreatEntity

    for ent in entities:
        name_key = ent.name.lower()
        etype_key = ent.entity_type if isinstance(ent.entity_type, str) else ent.entity_type.value

        if ent.confidence is not None and ent.confidence < min_confidence:
            continue

        if exclude_short_names and len(ent.name) <= 2:
            continue

        if name_key in NOISY_TOKENS:
            continue

        key = (name_key, etype_key)

        if key not in seen or (ent.confidence or 0) > (seen[key].confidence or 0):
            seen[key] = ent

    return list(seen.values())


class NERExtractor:
    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize the NER pipeline with the given model name or default.
        """
        if not model_name:
            model_name = r"D:\Local_model\CyNER-2.0-DeBERTa-v3-base"
        self.ner_pipeline = pipeline("ner", model=model_name, aggregation_strategy="simple")

    def extract_regex_entities(self, text: str) -> List[ThreatEntity]:
        """
        Extract entities using predefined regex patterns.
        """
        entities = []
        
        patterns = [
            (r'CVE-\d{4}-\d{4,7}', EntityType.VULNERABILITY, 0.9),
            (r'T\d{4}(?:\.\d{3})?', EntityType.MITRE_TECHNIQUE, 1.0),
            (r'\bAPT\d+\b', EntityType.THREAT_ACTOR, 0.85),
            (r'\b[\w-]+(Stealer|RAT|Malware|Bot)\b', EntityType.MALWARE, 0.8),
            (r'\b(Mimikatz|Cobalt Strike|Metasploit|Netcat|Meterpreter)\b', EntityType.TOOL, 0.8),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', EntityType.INDICATOR, 0.7),
            (r'\b[a-fA-F0-9]{32,64}\b', EntityType.INDICATOR, 0.7),
            (r'\b(EternalBlue|BlueKeep|Heartbleed)\b', EntityType.EXPLOIT, 0.85),
            (r'\b[a-zA-Z0-9_]+\.py\b', EntityType.TOOL, 0.75),
        ]
        
        for pattern, ent_type, confidence in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                entities.append(ThreatEntity(
                    name=match.group(),
                    entity_type=ent_type,
                    text=match.group(),
                    confidence=confidence
                ))
        return entities

    def extract_entities(self, text: str) -> List[ThreatEntity]:
        """
        Extract entities from text using both transformer NER and regex-based methods.
        """
        ner_results = self.ner_pipeline(text)
        entities: List[ThreatEntity] = []
        seen_spans: Set[Tuple[int, int]] = set()
        seen_entities: Set[Tuple[str, str]] = set()

        for ent in ner_results or []:
            if not isinstance(ent, dict):
                continue

            entity_group = ent.get("entity_group") or ent.get("entity")
            start = ent.get("start")
            end = ent.get("end")
            score = ent.get("score")

            if entity_group is None or start is None or end is None:
                continue
                
            entity_type = map_entity_label(entity_group)
            if not entity_type:
                continue

            span = (start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)

            entity_name = text[start:end].strip()
            if len(entity_name) < 2 or re.fullmatch(r'\W+', entity_name):
                continue
            key = (entity_name.lower(), entity_type)
            if key in seen_entities:
                continue
            seen_entities.add(key)

            entity = ThreatEntity(
                name=entity_name,
                entity_type=entity_type,
                text=entity_name,
                description="",
                aliases=[],
                mitre_id=None,
                mitre_name=None,
                confidence=score
            )
            entities.append(entity)

        # Add regex entities avoiding duplicates
        for regex_entity in self.extract_regex_entities(text):
            key = (regex_entity.name.lower(), regex_entity.entity_type)
            if key not in seen_entities:
                entities.append(regex_entity)
                seen_entities.add(key)

        return entities


def perform_hybrid_ner(text: str, model_name: Optional[str] = None) -> List[ThreatEntity]:
    """
    Entry point to perform NER using the hybrid approach.
    """
    extractor = NERExtractor(model_name=model_name)
    return extractor.extract_entities(text)
