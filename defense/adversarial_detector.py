"""
Adversarial Input Detector Module
Detects adversarial patterns in model inputs.
"""
import re
from typing import Dict, List, Any, Optional
from collections import Counter


class AdversarialDetector:
    """
    Detector for adversarial inputs targeting LLMs.

    Detects:
    - Character-level perturbations
    - Word-level obfuscation
    - Encoding-based attacks
    - Injection attempts
    """

    # Known adversarial patterns
    OBFUSCATION_PATTERNS = {
        "char_repeat": r'(.)\1{2,}',  # Repeated characters
        "char_swap": r'[A-Za-z]*[a-z][A-Z][A-Za-z]*',  # Unexpected case mixing
        "leet_speak": r'(l|i|3){2,}|(\$|5){2,}',  # Common leet substitutions
        "special_char_insert": r'[^\w\s]{3,}',  # Multiple special chars
    }

    INJECTION_INDICATORS = [
        "ignore instructions",
        "disregard",
        "new instruction",
        "override",
        "developer mode",
        "bypass",
        "no restriction",
        "forget your",
    ]

    def __init__(self, sensitivity: float = 0.6):
        """
        Args:
            sensitivity: Detection sensitivity (0-1, higher = more sensitive)
        """
        self.sensitivity = sensitivity
        self.detection_log = []

    def detect(self, text: str) -> Dict[str, Any]:
        """
        Detect adversarial patterns in input text.

        Args:
            text: Input text to analyze

        Returns:
            Detection results
        """
        results = {
            "is_adversarial": False,
            "confidence": 0.0,
            "detected_types": [],
            "suspicious_features": []
        }

        # Check obfuscation patterns
        obfuscation_score = self._check_obfuscation(text)
        if obfuscation_score > 0:
            results["detected_types"].append("obfuscation")
            results["suspicious_features"].append({
                "type": "obfuscation",
                "score": obfuscation_score
            })

        # Check injection indicators
        injection_score = self._check_injection(text)
        if injection_score > 0:
            results["detected_types"].append("injection")
            results["suspicious_features"].append({
                "type": "injection",
                "score": injection_score
            })

        # Check encoding anomalies
        encoding_score = self._check_encoding(text)
        if encoding_score > 0:
            results["detected_types"].append("encoding")
            results["suspicious_features"].append({
                "type": "encoding",
                "score": encoding_score
            })

        # Calculate overall adversarial score
        if results["suspicious_features"]:
            total_score = sum(f["score"] for f in results["suspicious_features"])
            results["confidence"] = min(1.0, total_score / len(results["suspicious_features"]))
            results["is_adversarial"] = results["confidence"] >= self.sensitivity

        self.detection_log.append({
            "text_length": len(text),
            "is_adversarial": results["is_adversarial"],
            "confidence": results["confidence"]
        })

        return results

    def _check_obfuscation(self, text: str) -> float:
        """Check for character-level obfuscation."""
        score = 0.0

        # Check character repeat patterns
        for pattern_name, pattern in self.OBFUSCATION_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                score += 0.2 * len(matches)

        # Check unusual character distribution
        char_counts = Counter(text.lower())
        total_chars = sum(char_counts.values())
        if total_chars > 0:
            # Check entropy (simplified)
            entropy = sum((count/total_chars) * (count/total_chars)
                         for count in char_counts.values())
            # Low entropy might indicate obfuscation
            if entropy > 0.1:  # Very common character distribution
                score += 0.1

        return min(1.0, score)

    def _check_injection(self, text: str) -> float:
        """Check for prompt injection indicators."""
        text_lower = text.lower()
        score = 0.0

        for indicator in self.INJECTION_INDICATORS:
            if indicator in text_lower:
                score += 0.25

        return min(1.0, score)

    def _check_encoding(self, text: str) -> float:
        """Check for encoding-based attacks."""
        score = 0.0

        # Check for hex encoding patterns
        if re.search(r'\\x[0-9a-fA-F]{2}', text):
            score += 0.3

        # Check for unicode escape patterns
        if re.search(r'\\u[0-9a-fA-F]{4}', text):
            score += 0.3

        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            # Simple heuristic for base64
            score += 0.2

        return min(1.0, score)

    def detect_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Detect adversarial patterns in multiple texts."""
        return [self.detect(text) for text in texts]

    def get_detection_rate(self) -> float:
        """Get proportion of inputs flagged as adversarial."""
        if not self.detection_log:
            return 0.0
        return sum(1 for log in self.detection_log if log["is_adversarial"]) / len(self.detection_log)
