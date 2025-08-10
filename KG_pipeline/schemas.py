from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
from datetime import datetime
import uuid


class EntityType(str, Enum):
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    VULNERABILITY = "vulnerability"
    TTP = "ttp"
    TOOL = "tool"
    SCRIPT = "script"
    INDICATOR = "indicator"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"
    EXPLOIT = "exploit"
    LOCATION = "location"
    ORGANIZATION = "organization"
    PERSON = "person"
    MISC = "miscellaneous"


class RelationshipType(str, Enum):
    USES = "uses"
    TARGETS = "targets"
    EXPLOITS = "exploits"
    COMMUNICATES_WITH = "communicates_with"
    DERIVES_FROM = "derives_from"
    ASSOCIATED_WITH = "associated_with"
    DETECTS = "detects"
    RELATED_TO = "related_to"  # Add as needed


@dataclass
class ThreatEntity:
    """
    Represents an entity extracted from threat intelligence text.
    """
    name: str
    type: EntityType
    text: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    external_references: Optional[List[str]] = field(default_factory=list)
    severity: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    run_id: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))  # Unique ID for deduplication


    def __post_init__(self):
        self.name = self.name.strip().lower()
        self.aliases = [alias.strip().lower() for alias in self.aliases]


@dataclass
class ThreatRelationship:
    """
    Represents a directed relationship between two ThreatEntities.
    """
    source_name: str
    source_type: EntityType
    target_name: str
    target_type: EntityType
    relationship_type: RelationshipType
    description: Optional[str] = None
    confidence: Optional[float] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    run_id: Optional[str] = None

    def __post_init__(self):
        self.source_name = self.source_name.strip().lower()
        self.target_name = self.target_name.strip().lower()

def map_entity_label(label: str) -> Optional[str]:
    """
    Map raw NER labels to standardized EntityType strings.
    """
    if not label:
        return None

    mapping = {
        "org": EntityType.ORGANIZATION.value,
        "organization": EntityType.ORGANIZATION.value,
        "threat_actor": EntityType.THREAT_ACTOR.value,
        "per": EntityType.PERSON.value,
        "person": EntityType.PERSON.value,
        "loc": EntityType.LOCATION.value,
        "location": EntityType.LOCATION.value,
        "misc": EntityType.MISC.value,
        "miscellaneous": EntityType.MISC.value,
        "cve": EntityType.CVE.value,
        "ttp": EntityType.TTP.value,
        "mitre_technique": EntityType.MITRE_TECHNIQUE.value,
        "malware": EntityType.MALWARE.value,
        "tool": EntityType.TOOL.value,
        "script": EntityType.SCRIPT.value,
        "exploit": EntityType.EXPLOIT.value,
        "indicator": EntityType.INDICATOR.value,
    }

    return mapping.get(label.lower())
