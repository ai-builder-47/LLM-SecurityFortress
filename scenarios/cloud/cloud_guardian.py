"""
Cloud Deployment Security Module
Security guardian for cloud-based LLM deployments.
"""
from typing import Dict, List, Any, Optional
from ...defense import OutputFilter, PIIDetector, SemanticGuard, AdversarialDetector


class CloudGuardian:
    """
    Security guardian for cloud LLM deployments.

    Provides comprehensive security for cloud API-based LLM services:
    - Input validation and sanitization
    - Output filtering and PII redaction
    - Semantic safety analysis
    - Rate limiting and abuse detection
    """

    def __init__(self, strict_mode: bool = False):
        """
        Args:
            strict_mode: Enable strict security policies
        """
        self.strict_mode = strict_mode

        # Initialize defense components
        self.output_filter = OutputFilter(strict_mode=strict_mode)
        self.pii_detector = PIIDetector()
        self.semantic_guard = SemanticGuard()
        self.adversarial_detector = AdversarialDetector()

        # Request tracking
        self.request_log = []
        self.blocked_requests = 0

    def protect_input(self, user_input: str) -> Dict[str, Any]:
        """
        Protect against malicious input.

        Args:
            user_input: Raw user input

        Returns:
            Protection result with sanitized input and threat info
        """
        result = {
            "original_input": user_input,
            "is_safe": True,
            "threats_detected": [],
            "sanitized_input": user_input,
            "action": "allow"
        }

        # Check for adversarial patterns
        adversarial = self.adversarial_detector.detect(user_input)
        if adversarial["is_adversarial"]:
            result["is_safe"] = False
            result["threats_detected"].append({
                "type": "adversarial",
                "confidence": adversarial["confidence"]
            })
            result["action"] = "block"
            self.blocked_requests += 1
            return result

        # Check semantic safety
        semantic = self.semantic_guard.analyze(user_input)
        if not semantic["is_safe"]:
            result["threats_detected"].append({
                "type": "semantic",
                "categories": semantic["flagged_categories"],
                "confidence": semantic["confidence"]
            })
            if self.strict_mode:
                result["action"] = "block"
                self.blocked_requests += 1
            else:
                result["action"] = "warn"

        self.request_log.append({"type": "input", "input_length": len(user_input)})
        return result

    def protect_output(self, model_output: str) -> Dict[str, Any]:
        """
        Protect against unsafe model output.

        Args:
            model_output: Raw model output

        Returns:
            Protection result with filtered output and PII info
        """
        result = {
            "original_output": model_output,
            "is_safe": True,
            "issues_detected": [],
            "filtered_output": model_output,
            "pii_redacted": False,
            "action": "allow"
        }

        # Filter harmful content
        filtered = self.output_filter.filter(model_output)
        if not filtered["is_safe"]:
            result["is_safe"] = False
            result["issues_detected"].append({
                "type": "harmful_content",
                "categories": filtered["flagged_categories"]
            })
            result["action"] = "block"
            self.blocked_requests += 1
            return result

        # Detect and redact PII
        pii_result = self.pii_detector.detect_and_redact(model_output)
        if pii_result["entities_detected"] > 0:
            result["pii_redacted"] = True
            result["filtered_output"] = pii_result["redacted"]
            result["issues_detected"].append({
                "type": "pii_detected",
                "count": pii_result["entities_detected"],
                "types": pii_result["pii_types_found"]
            })

        self.request_log.append({"type": "output", "output_length": len(model_output)})
        return result

    def process(self, user_input: str, model_output: str) -> Dict[str, Any]:
        """
        Process complete request-response cycle.

        Args:
            user_input: User input
            model_output: Model output

        Returns:
            Complete security assessment
        """
        input_protection = self.protect_input(user_input)
        output_protection = self.protect_output(model_output)

        final_action = "allow"
        if input_protection["action"] == "block" or output_protection["action"] == "block":
            final_action = "block"
        elif input_protection["action"] == "warn" or output_protection["action"] == "warn":
            final_action = "warn"

        return {
            "input_protection": input_protection,
            "output_protection": output_protection,
            "overall_action": final_action,
            "blocked": final_action == "block"
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get guardian statistics."""
        return {
            "total_requests": len(self.request_log),
            "blocked_requests": self.blocked_requests,
            "block_rate": self.blocked_requests / max(len(self.request_log), 1),
            "defense_stats": {
                "output_filter": self.output_filter.get_stats(),
                "pii_detector": self.pii_detector.get_stats(),
                "semantic_guard": self.semantic_guard.get_guard_stats()
            }
        }
