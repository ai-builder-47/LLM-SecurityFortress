"""
Car-side (Automotive) Security Module
Security guardian for automotive LLM deployments.
"""
from typing import Dict, List, Any
from ...defense import OutputFilter, SemanticGuard, AdversarialDetector


class CarShield:
    """
    Security shield for automotive LLM deployments.

    Special considerations for car-side deployment:
    - Low latency requirements
    - Real-time processing
    - Safety-critical context
    - Limited computational resources
    """

    def __init__(self, latency_mode: str = "balanced"):
        """
        Args:
            latency_mode: Processing mode - "fast", "balanced", "thorough"
        """
        self.latency_mode = latency_mode

        # Simplified defense components for car-side
        self.semantic_guard = SemanticGuard()
        self.adversarial_detector = AdversarialDetector()

        # Latency settings
        self.latency_targets = {
            "fast": 10,      # 10ms max
            "balanced": 50,  # 50ms max
            "thorough": 100  # 100ms max
        }

        # Car-specific safety rules
        self.safety_rules = {
            "navigation_override": ["ignore route", "change destination", "wrong direction"],
            "control_command": ["accelerate", "brake", "steer", "control"],
            "safety_bypass": ["disable", "turn off", "bypass safety"]
        }

        self.processing_log = []

    def protect_input(self, user_input: str) -> Dict[str, Any]:
        """
        Process input with car-side optimizations.

        Args:
            user_input: Voice or text input from car interface

        Returns:
            Security assessment with latency info
        """
        import time
        start_time = time.time()

        result = {
            "is_safe": True,
            "threats_detected": [],
            "action": "allow",
            "latency_ms": 0
        }

        # Quick adversarial check
        adversarial = self.adversarial_detector.detect(user_input)
        if adversarial["is_adversarial"]:
            result["is_safe"] = False
            result["threats_detected"].append({
                "type": "adversarial",
                "confidence": adversarial["confidence"]
            })
            result["action"] = "block"
            return result

        # Check car-specific safety rules
        input_lower = user_input.lower()
        for rule_category, keywords in self.safety_rules.items():
            for keyword in keywords:
                if keyword in input_lower:
                    result["threats_detected"].append({
                        "type": "safety_rule",
                        "category": rule_category,
                        "keyword": keyword
                    })
                    if rule_category in ["control_command", "safety_bypass"]:
                        result["action"] = "block"
                        result["is_safe"] = False
                    break

        # Semantic analysis only in thorough/balanced mode
        if self.latency_mode in ["thorough", "balanced"]:
            semantic = self.semantic_guard.analyze(user_input)
            if not semantic["is_safe"]:
                result["threats_detected"].append({
                    "type": "semantic",
                    "categories": semantic["flagged_categories"]
                })

        result["latency_ms"] = int((time.time() - start_time) * 1000)
        self.processing_log.append(result)

        return result

    def process_voice(self, voice_input: str) -> Dict[str, Any]:
        """
        Process voice command input.

        Args:
            voice_input: Transcribed voice input

        Returns:
            Security result with command validation
        """
        result = self.protect_input(voice_input)
        result["input_type"] = "voice"
        return result

    def process_text(self, text_input: str) -> Dict[str, Any]:
        """
        Process text input from car interface.

        Args:
            text_input: Text input from touchscreen/keypad

        Returns:
            Security result
        """
        result = self.protect_input(text_input)
        result["input_type"] = "text"
        return result

    def validate_command(self, command: str) -> Dict[str, Any]:
        """
        Validate safety-critical commands.

        Args:
            command: Command to validate

        Returns:
            Command validation result
        """
        result = {
            "command": command,
            "is_valid": True,
            "validation_errors": []
        }

        # Check for dangerous commands
        command_lower = command.lower()

        if "control" in command_lower or "override" in command_lower:
            result["is_valid"] = False
            result["validation_errors"].append("Safety-critical commands not allowed from external input")

        if any(bypass in command_lower for bypass in ["disable safety", "turn off protection"]):
            result["is_valid"] = False
            result["validation_errors"].append("Safety system bypass not permitted")

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get car shield statistics."""
        if not self.processing_log:
            return {"total_processed": 0, "avg_latency_ms": 0}

        total = len(self.processing_log)
        avg_latency = sum(log.get("latency_ms", 0) for log in self.processing_log) / total
        blocked = sum(1 for log in self.processing_log if log["action"] == "block")

        return {
            "total_processed": total,
            "blocked": blocked,
            "avg_latency_ms": avg_latency,
            "within_latency_target": sum(
                1 for log in self.processing_log
                if log.get("latency_ms", 0) <= self.latency_targets.get(self.latency_mode, 100)
            )
        }
