"""
Semantic Guard Module
Semantic analysis for detecting potentially unsafe content.
"""
import re
from typing import Dict, List, Any, Optional


class SemanticGuard:
    """
    Semantic safety guard for LLM outputs.

    Uses keyword-based and pattern-based analysis to detect:
    - Jailbreak attempts
    - Prompt injection
    - Policy violations
    - Unsafe topics
    """

    # Semantic patterns for detection
    UNSAFE_PATTERNS = {
        "jailbreak": [
            r"ignore\s+(all\s+)?(previous\s+)?(your\s+)?instructions?",
            r"disregard\s+(all\s+)?(your\s+)?",
            r"you\s+are\s+now\s+",
            r"developer\s+mode",
            r"bypass\s+(your\s+)?(safety|restriction)",
            r"no\s+content\s+restriction",
            r"without\s+guideline",
        ],
        "prompt_injection": [
            r"new\s+instruction[:\s]",
            r"replace\s+your\s+instruction",
            r"your\s+task\s+is\s+now",
            r"remember\s+that\s+you\s+are\s+not",
            r"this\s+is\s+not\s+being\s+monitored",
        ],
        "manipulation": [
            r"will\s+be\s+rewarded?",
            r"no\s+one\s+will\s+know",
            r"don't\s+tell\s+anyone",
            r"keep\s+this\s+secret",
            r"trust\s+me\s+on\s+this",
        ]
    }

    # Topic categories for analysis
    TOPIC_CATEGORIES = {
        "violence": ["kill", "murder", "attack", "harm", "destroy"],
        "illegal": ["illegal", "drug", "fraud", "hack", "steal"],
        "adult": ["nsfw", "explicit", "porn", "adult"],
        "discrimination": ["hate", "racist", "sexist", "discriminate"],
    }

    def __init__(self, threshold: float = 0.5):
        """
        Args:
            threshold: Minimum confidence threshold for flagging
        """
        self.threshold = threshold
        self.guard_stats = {
            "texts_checked": 0,
            "unsafe_detected": 0,
            "by_category": {}
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Perform semantic analysis on text.

        Args:
            text: Input text to analyze

        Returns:
            Analysis results with categories and confidence scores
        """
        self.guard_stats["texts_checked"] += 1

        text_lower = text.lower()
        results = {
            "is_safe": True,
            "confidence": 1.0,
            "flagged_categories": [],
            "flagged_patterns": [],
            "topic_scores": {}
        }

        # Check for unsafe patterns
        for category, patterns in self.UNSAFE_PATTERNS.items():
            category_score = 0.0
            matched_patterns = []

            for pattern in patterns:
                if re.search(pattern, text_lower):
                    category_score += 0.3
                    matched_patterns.append(pattern)

            if matched_patterns:
                results["flagged_categories"].append(category)
                results["flagged_patterns"].extend(matched_patterns)
                self.guard_stats["by_category"][category] = \
                    self.guard_stats["by_category"].get(category, 0) + 1

        # Check topic categories
        for topic, keywords in self.TOPIC_CATEGORIES.items():
            topic_score = sum(1 for kw in keywords if kw in text_lower) / len(keywords)
            results["topic_scores"][topic] = topic_score

            if topic_score >= self.threshold:
                results["flagged_categories"].append(f"topic_{topic}")
                self.guard_stats["by_category"][f"topic_{topic}"] = \
                    self.guard_stats["by_category"].get(f"topic_{topic}", 0) + 1

        # Determine safety
        if results["flagged_categories"]:
            results["is_safe"] = False
            results["confidence"] = min(1.0, len(results["flagged_categories"]) * 0.2)
            self.guard_stats["unsafe_detected"] += 1

        return results

    def analyze_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple texts."""
        return [self.analyze(text) for text in texts]

    def get_guard_stats(self) -> Dict[str, Any]:
        """Get guard statistics."""
        return self.guard_stats.copy()

    def reset_stats(self) -> None:
        """Reset guard statistics."""
        self.guard_stats = {
            "texts_checked": 0,
            "unsafe_detected": 0,
            "by_category": {}
        }


class SafetyChecker:
    """High-level safety checking with configurable policies."""

    def __init__(self, policy_level: str = "standard"):
        """
        Args:
            policy_level: Policy strictness - "relaxed", "standard", "strict"
        """
        self.policy_level = policy_level
        self.thresholds = {
            "relaxed": 0.7,
            "standard": 0.5,
            "strict": 0.3
        }
        self.guard = SemanticGuard(threshold=self.thresholds.get(policy_level, 0.5))

    def check(self, text: str) -> Dict[str, Any]:
        """Check text against safety policy."""
        return self.guard.analyze(text)

    def check_with_action(self, text: str) -> Dict[str, Any]:
        """Check text and recommend action."""
        result = self.check(text)

        if not result["is_safe"]:
            if self.policy_level == "strict":
                result["action"] = "block"
            elif self.policy_level == "standard":
                result["action"] = "warn"
            else:
                result["action"] = "allow_with_warning"
        else:
            result["action"] = "allow"

        return result
