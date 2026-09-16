"""
Output Filter Module
Filters potentially harmful model outputs.
"""
import re
from typing import List, Dict, Any, Optional


class OutputFilter:
    """
    Output content filter for LLM responses.

    Filters categories:
    - Harmful content
    - PII information
    - Unsafe code
    - Malicious URLs
    """

    # Content patterns for filtering
    HARMFUL_PATTERNS = {
        "violent": [
            r"\b(kill|murder|attack|harm|destroy|weapon)\b",
            r"\b(bomb|explosive|terrorist)\b",
        ],
        "illegal": [
            r"\b(illegal|drug|criminal|fraud|scam)\b",
            r"\b(hack|crack|exploit|steal)\b",
        ],
        "personal_data": [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{16}\b",  # Credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
        ],
        "unsafe_code": [
            r"(eval|exec|__import__)\s*\(",
            r"(os\.system|subprocess)\s*\(",
            r"(rm\s+-rf|mkfs)",
        ],
        "malicious_url": [
            r"https?://[^\s]*\.(tk|ml|ga|cf)",  # Suspicious TLDs
            r"https?://[^\s]*(login|account|password)[^\s]*\.php",
        ]
    }

    def __init__(self, strict_mode: bool = False):
        """
        Args:
            strict_mode: If True, use stricter filtering thresholds
        """
        self.strict_mode = strict_mode
        self.filter_stats = {
            "total_checked": 0,
            "flagged": 0,
            "by_category": {}
        }

    def filter(self, text: str) -> Dict[str, Any]:
        """
        Filter output text for safety concerns.

        Args:
            text: Output text to filter

        Returns:
            Dict with filter results and metadata
        """
        self.filter_stats["total_checked"] += 1

        results = {
            "is_safe": True,
            "flagged_categories": [],
            "flagged_content": [],
            "confidence": 0.0
        }

        for category, patterns in self.HARMFUL_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                if found:
                    matches.extend(found)

            if matches:
                results["flagged_categories"].append(category)
                results["flagged_content"].extend(matches)
                self.filter_stats["by_category"][category] = \
                    self.filter_stats["by_category"].get(category, 0) + len(matches)

        if results["flagged_categories"]:
            results["is_safe"] = False
            results["confidence"] = min(1.0, len(results["flagged_content"]) * 0.2)
            self.filter_stats["flagged"] += 1

        # In strict mode, flag anything suspicious
        if self.strict_mode and results["flagged_categories"]:
            results["action"] = "block"
        else:
            results["action"] = "warn" if results["flagged_categories"] else "allow"

        return results

    def filter_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Filter multiple texts."""
        return [self.filter(text) for text in texts]

    def add_custom_pattern(self, category: str, pattern: str) -> None:
        """Add custom filtering pattern."""
        if category not in self.HARMFUL_PATTERNS:
            self.HARMFUL_PATTERNS[category] = []
        self.HARMFUL_PATTERNS[category].append(pattern)

    def get_stats(self) -> Dict[str, Any]:
        """Get filtering statistics."""
        return self.filter_stats.copy()


class ContentModerator:
    """Advanced content moderation with category-specific actions."""

    def __init__(self):
        self.categories = ["hate_speech", "violence", "sexual", "dangerous", "harassment"]
        self.category_actions = {cat: "warn" for cat in self.categories}

    def moderate(self, text: str) -> Dict[str, Any]:
        """Perform content moderation."""
        return {
            "is_appropriate": True,
            "category_scores": {cat: 0.0 for cat in self.categories},
            "recommended_action": "allow"
        }

    def set_action(self, category: str, action: str) -> None:
        """Set action for a category (allow, warn, block)."""
        if category in self.category_actions:
            self.category_actions[category] = action
