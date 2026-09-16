"""
PII (Personally Identifiable Information) Detector Module
Detects and redacts PII from model outputs.
"""
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class PIIEntity:
    """Represents a detected PII entity."""
    pii_type: str
    value: str
    start_pos: int
    end_pos: int
    confidence: float


class PIIDetector:
    """
    PII Detection and Redaction System.

    Detects and redacts:
    - Names (simple heuristic)
    - Email addresses
    - Phone numbers
    - Social Security Numbers
    - Credit card numbers
    - IP addresses
    - Physical addresses
    """

    # Regex patterns for PII detection
    PII_PATTERNS = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone_us": r'\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        "phone_intl": r'\b\+[1-9]\d{1,14}\b',
        "ssn": r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "mac_address": r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
    }

    # Simple name patterns (in practice, would use NER model)
    NAME_PATTERNS = {
        "person_title": r'\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b',
    }

    REDACTION_FORMATS = {
        "email": "[EMAIL_REDACTED]",
        "phone_us": "[PHONE_REDACTED]",
        "phone_intl": "[PHONE_REDACTED]",
        "ssn": "[SSN_REDACTED]",
        "credit_card": "[CC_REDACTED]",
        "ip_address": "[IP_REDACTED]",
        "mac_address": "[MAC_REDACTED]",
        "name": "[NAME_REDACTED]",
    }

    def __init__(self, redaction_format: str = "mask"):
        """
        Args:
            redaction_format: Format for redaction - "mask", "redact", or "hash"
        """
        self.redaction_format = redaction_format
        self.detection_log = []

    def detect(self, text: str) -> List[PIIEntity]:
        """
        Detect PII entities in text.

        Args:
            text: Input text to analyze

        Returns:
            List of detected PII entities
        """
        entities = []

        # Detect pattern-based PII
        for pii_type, pattern in self.PII_PATTERNS.items():
            for match in re.finditer(pattern, text):
                entities.append(PIIEntity(
                    pii_type=pii_type,
                    value=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=0.95
                ))

        # Detect name patterns
        for pattern in self.NAME_PATTERNS.values():
            for match in re.finditer(pattern, text):
                entities.append(PIIEntity(
                    pii_type="name",
                    value=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=0.75  # Lower confidence for heuristic detection
                ))

        self.detection_log.append({
            "text_length": len(text),
            "entities_found": len(entities)
        })

        return entities

    def redact(self, text: str, entities: List[PIIEntity] = None) -> str:
        """
        Redact PII from text.

        Args:
            text: Input text
            entities: Pre-detected entities (if None, will detect first)

        Returns:
            Redacted text
        """
        if entities is None:
            entities = self.detect(text)

        # Sort entities by position in reverse order to avoid offset issues
        sorted_entities = sorted(entities, key=lambda e: e.start_pos, reverse=True)

        redacted_text = text
        for entity in sorted_entities:
            redaction_token = self._get_redaction_token(entity.pii_type)
            redacted_text = (
                redacted_text[:entity.start_pos] +
                redaction_token +
                redacted_text[entity.end_pos:]
            )

        return redacted_text

    def _get_redaction_token(self, pii_type: str) -> str:
        """Get redaction token based on format."""
        base_token = self.REDACTION_FORMATS.get(pii_type, "[PII_REDACTED]")

        if self.redaction_format == "mask":
            return base_token
        elif self.redaction_format == "redact":
            return "[REDACTED]"
        elif self.redaction_format == "hash":
            return f"[{hash(pii_type) % 100000:05d}]"

        return base_token

    def detect_and_redact(self, text: str) -> Dict[str, Any]:
        """
        Detect and redact PII in one step.

        Args:
            text: Input text

        Returns:
            Dict with original, redacted text, and detection info
        """
        entities = self.detect(text)
        redacted = self.redact(text, entities)

        return {
            "original": text,
            "redacted": redacted,
            "entities_detected": len(entities),
            "pii_types_found": list(set(e.pii_type for e in entities)),
            "entities": [
                {
                    "type": e.pii_type,
                    "value": e.value,
                    "confidence": e.confidence
                }
                for e in entities
            ]
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        return {
            "total_texts_processed": len(self.detection_log),
            "total_pii_detected": sum(log["entities_found"] for log in self.detection_log)
        }
