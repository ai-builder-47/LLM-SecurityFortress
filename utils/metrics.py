"""
Security Metrics Module
Provides quantitative metrics for evaluating model security.
"""
import numpy as np
from typing import Dict, List, Tuple


class SecurityMetrics:
    """Calculate security evaluation metrics."""

    @staticmethod
    def attack_success_rate(original_output: str, perturbed_output: str, target_label: str = None) -> float:
        """
        Calculate attack success rate.
        Returns 1.0 if attack successfully changed model behavior, 0.0 otherwise.
        """
        if original_output == perturbed_output:
            return 0.0
        if target_label:
            return 1.0 if target_label in perturbed_output else 0.0
        return 1.0

    @staticmethod
    def defense_block_rate(attacks_detected: int, total_attacks: int) -> float:
        """Calculate defense block rate."""
        if total_attacks == 0:
            return 0.0
        return attacks_detected / total_attacks

    @staticmethod
    def false_positive_rate(normal_inputs: List[str], false_alarms: int) -> float:
        """Calculate false positive rate for defense systems."""
        if len(normal_inputs) == 0:
            return 0.0
        return false_alarms / len(normal_inputs)

    @staticmethod
    def robustness_score(attack_success_rates: List[float], defense_block_rates: List[float]) -> float:
        """
        Calculate overall robustness score.
        Higher score = more robust model.
        Score range: [0, 1]
        """
        if not attack_success_rates or not defense_block_rates:
            return 0.0

        avg_attack_success = np.mean(attack_success_rates)
        avg_defense_block = np.mean(defense_block_rates)

        # Robustness = 1 - attack_success + defense_block / 2
        robustness = (1 - avg_attack_success) * 0.5 + avg_defense_block * 0.5
        return robustness

    @staticmethod
    def calculate_security_score(
        attack_results: Dict[str, float],
        defense_results: Dict[str, float],
        scenario_weights: Dict[str, float] = None
    ) -> Dict[str, float]:
        """
        Calculate comprehensive security score.

        Args:
            attack_results: Dict of attack_type -> success_rate
            defense_results: Dict of defense_type -> block_rate
            scenario_weights: Optional weights for different scenarios

        Returns:
            Dict containing overall_score, attack_score, defense_score
        """
        if scenario_weights is None:
            scenario_weights = {"cloud": 0.4, "car": 0.3, "mobile": 0.3}

        attack_score = 1 - np.mean(list(attack_results.values())) if attack_results else 0.0
        defense_score = np.mean(list(defense_results.values())) if defense_results else 0.0

        overall_score = attack_score * 0.5 + defense_score * 0.5

        return {
            "overall_score": round(overall_score, 4),
            "attack_score": round(attack_score, 4),
            "defense_score": round(defense_score, 4),
            "attack_details": attack_results,
            "defense_details": defense_results
        }

    @staticmethod
    def generate_report(metrics: Dict[str, float], scenario: str) -> str:
        """Generate human-readable security report."""
        report = f"""
=== Security Evaluation Report: {scenario.upper()} ===
Overall Security Score: {metrics.get('overall_score', 0):.2%}
Attack Resistance Score: {metrics.get('attack_score', 0):.2%}
Defense Effectiveness Score: {metrics.get('defense_score', 0):.2%}

Attack Details:
{chr(10).join(f"  - {k}: {v:.2%}" for k, v in metrics.get('attack_details', {}).items())}

Defense Details:
{chr(10).join(f"  - {k}: {v:.2%}" for k, v in metrics.get('defense_details', {}).items())}
"""
        return report
