"""
Mobile Deployment Security Module
Security guardian for mobile LLM deployments.
"""
from typing import Dict, List, Any
from ...defense import OutputFilter, PIIDetector, SemanticGuard, AdversarialDetector


class MobileGuard:
    """
    Security guardian for mobile LLM deployments.

    Special considerations for mobile deployment:
    - On-device processing for privacy
    - Battery efficiency
    - Privacy-first architecture
    - Offline capability
    """

    def __init__(self, privacy_level: str = "high"):
        """
        Args:
            privacy_level: Privacy strictness - "low", "medium", "high"
        """
        self.privacy_level = privacy_level

        # Initialize defense components
        self.output_filter = OutputFilter()
        self.pii_detector = PIIDetector(redaction_format="mask")
        self.semantic_guard = SemanticGuard()
        self.adversarial_detector = AdversarialDetector()

        # Privacy settings
        self.privacy_actions = {
            "low": {"pii_redact": False, "local_only": False},
            "medium": {"pii_redact": True, "local_only": True},
            "high": {"pii_redact": True, "local_only": True, "strict_filtering": True}
        }

        self.request_log = []

    def protect_input(self, user_input: str) -> Dict[str, Any]:
        """
        Protect against malicious input with privacy focus.

        Args:
            user_input: User input from mobile app

        Returns:
            Protection result
        """
        result = {
            "is_safe": True,
            "threats_detected": [],
            "action": "allow",
            "privacy_level": self.privacy_level
        }

        # Adversarial detection
        adversarial = self.adversarial_detector.detect(user_input)
        if adversarial["is_adversarial"]:
            result["is_safe"] = False
            result["threats_detected"].append({
                "type": "adversarial",
                "confidence": adversarial["confidence"]
            })
            result["action"] = "block"
            return result

        # Semantic safety check
        semantic = self.semantic_guard.analyze(user_input)
        if not semantic["is_safe"]:
            result["threats_detected"].append({
                "type": "semantic",
                "categories": semantic["flagged_categories"]
            })
            if self.privacy_level == "high":
                result["action"] = "warn"

        self.request_log.append({"type": "input"})
        return result

    def protect_output(self, model_output: str) -> Dict[str, Any]:
        """
        Protect against unsafe model output with privacy focus.

        Args:
            model_output: Model output to process

        Returns:
            Protection result with privacy protection
        """
        result = {
            "original_output": model_output,
            "is_safe": True,
            "issues_detected": [],
            "protected_output": model_output,
            "privacy_applied": False
        }

        # Content filtering
        filtered = self.output_filter.filter(model_output)
        if not filtered["is_safe"]:
            result["is_safe"] = False
            result["issues_detected"].append({
                "type": "harmful_content",
                "categories": filtered["flagged_categories"]
            })
            result["action"] = "block"
            return result

        # PII redaction based on privacy level
        privacy_config = self.privacy_actions.get(self.privacy_level, {})
        if privacy_config.get("pii_redact", False):
            pii_result = self.pii_detector.detect_and_redact(model_output)
            if pii_result["entities_detected"] > 0:
                result["protected_output"] = pii_result["redacted"]
                result["privacy_applied"] = True
                result["issues_detected"].append({
                    "type": "pii_protected",
                    "count": pii_result["entities_detected"]
                })

        self.request_log.append({"type": "output"})
        return result

    def process(self, user_input: str, model_output: str) -> Dict[str, Any]:
        """
        Process complete mobile request.

        Args:
            user_input: User input
            model_output: Model output

        Returns:
            Complete security and privacy assessment
        """
        input_prot = self.protect_input(user_input)
        output_prot = self.protect_output(model_output)

        final_action = "allow"
        if input_prot["action"] == "block" or output_prot.get("action") == "block":
            final_action = "block"
        elif input_prot["action"] == "warn":
            final_action = "warn"

        return {
            "input_protection": input_prot,
            "output_protection": output_prot,
            "overall_action": final_action,
            "privacy_level": self.privacy_level,
            "local_only": self.privacy_actions.get(self.privacy_level, {}).get("local_only", False)
        }

    def check_data_privacy(self, text: str) -> Dict[str, Any]:
        """
        Check and protect data privacy in text.

        Args:
            text: Text to check for privacy issues

        Returns:
            Privacy assessment
        """
        pii_result = self.pii_detector.detect_and_redact(text)

        return {
            "has_pii": pii_result["entities_detected"] > 0,
            "pii_types": pii_result["pii_types_found"],
            "redacted_text": pii_result["redacted"],
            "privacy_score": 1.0 - (pii_result["entities_detected"] * 0.1)
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get mobile guard statistics."""
        total = len(self.request_log)
        return {
            "total_requests": total,
            "privacy_level": self.privacy_level,
            "requests_by_type": {
                "input": sum(1 for r in self.request_log if r["type"] == "input"),
                "output": sum(1 for r in self.request_log if r["type"] == "output")
            }
        }
