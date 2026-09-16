"""
Security Pipeline Module
Orchestrates security operations across attack, defense, and evaluation.
"""
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass


@dataclass
class PipelineStage:
    """Represents a stage in the security pipeline."""
    name: str
    processor: Callable
    enabled: bool = True


class SecurityPipeline:
    """
    Orchestrates security operations for LLM deployments.

    Pipeline stages:
    1. Input Validation - Check for adversarial patterns
    2. Attack Simulation - Simulate attacks for testing
    3. Defense Application - Apply security defenses
    4. Output Filtering - Filter model outputs
    5. Evaluation - Assess security effectiveness
    """

    def __init__(self, scenario: str = "cloud"):
        """
        Args:
            scenario: Deployment scenario (cloud, car, mobile)
        """
        self.scenario = scenario
        self.stages: List[PipelineStage] = []
        self.pipeline_log = []

        # Default stages will be added based on scenario
        self._initialize_stages()

    def _initialize_stages(self) -> None:
        """Initialize pipeline stages based on scenario."""
        if self.scenario == "cloud":
            from ..scenarios.cloud import CloudGuardian
            self.guardian = CloudGuardian()
        elif self.scenario == "car":
            from ..scenarios.car import CarShield
            self.guardian = CarShield()
        elif self.scenario == "mobile":
            from ..scenarios.mobile import MobileGuard
            self.guardian = MobileGuard()
        else:
            from ..scenarios.cloud import CloudGuardian
            self.guardian = CloudGuardian()

    def add_stage(self, name: str, processor: Callable) -> None:
        """Add a custom stage to the pipeline."""
        self.stages.append(PipelineStage(name=name, processor=processor))

    def remove_stage(self, name: str) -> None:
        """Remove a stage from the pipeline."""
        self.stages = [s for s in self.stages if s.name != name]

    def process(self, user_input: str, model_output: str = None) -> Dict[str, Any]:
        """
        Process input through the security pipeline.

        Args:
            user_input: User input to process
            model_output: Optional model output to process

        Returns:
            Pipeline processing results
        """
        result = {
            "scenario": self.scenario,
            "input": user_input,
            "output": model_output,
            "stage_results": {},
            "overall_action": "allow",
            "blocked": False
        }

        # Use scenario-specific guardian for core processing
        if model_output:
            core_result = self.guardian.process(user_input, model_output)
            result["stage_results"]["guardian"] = core_result
            result["overall_action"] = core_result.get("overall_action", "allow")
            result["blocked"] = core_result.get("blocked", False)
        else:
            input_prot = self.guardian.protect_input(user_input)
            result["stage_results"]["input_protection"] = input_prot
            result["overall_action"] = input_prot.get("action", "allow")
            result["blocked"] = input_prot.get("action") == "block"

        # Process through custom stages
        for stage in self.stages:
            if stage.enabled:
                try:
                    stage_result = stage.processor(user_input, model_output)
                    result["stage_results"][stage.name] = stage_result
                except Exception as e:
                    result["stage_results"][stage.name] = {"error": str(e)}

        self.pipeline_log.append(result)
        return result

    def process_batch(self, inputs: List[tuple]) -> List[Dict[str, Any]]:
        """
        Process multiple inputs through the pipeline.

        Args:
            inputs: List of (user_input, model_output) tuples

        Returns:
            List of processing results
        """
        return [self.process(inp, out) for inp, out in inputs]

    def evaluate_pipeline(self) -> Dict[str, Any]:
        """
        Evaluate pipeline effectiveness.

        Returns:
            Evaluation results
        """
        if not self.pipeline_log:
            return {"message": "No pipeline runs to evaluate"}

        total = len(self.pipeline_log)
        blocked = sum(1 for r in self.pipeline_log if r["blocked"])

        return {
            "scenario": self.scenario,
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate": blocked / max(total, 1),
            "stages_count": len(self.stages),
            "stage_names": [s.name for s in self.stages]
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            "scenario": self.scenario,
            "total_runs": len(self.pipeline_log),
            "stages": [s.name for s in self.stages],
            "guardian_stats": self.guardian.get_stats()
        }


class AttackDefensePipeline(SecurityPipeline):
    """
    Extended pipeline with attack simulation capabilities.

    Useful for testing defense effectiveness.
    """

    def __init__(self, scenario: str = "cloud"):
        super().__init__(scenario)
        self.attack_results = []
        self.defense_results = []

    def simulate_attack(
        self,
        attack_module,
        test_prompts: List[str]
    ) -> Dict[str, Any]:
        """
        Simulate attacks and measure defense effectiveness.

        Args:
            attack_module: Attack module to use
            test_prompts: List of prompts to attack

        Returns:
            Attack simulation results
        """
        results = {
            "scenario": self.scenario,
            "attack_type": attack_module.__class__.__name__,
            "prompts_tested": len(test_prompts),
            "defense_blocked": 0,
            "attack_successes": 0
        }

        for prompt in test_prompts:
            # Generate adversarial version
            adversarial = attack_module.generate(prompt)

            # Process through pipeline
            pipeline_result = self.process(prompt, adversarial)

            if pipeline_result["blocked"]:
                results["defense_blocked"] += 1
            else:
                results["attack_successes"] += 1

        results["defense_rate"] = results["defense_blocked"] / max(len(test_prompts), 1)
        results["attack_success_rate"] = results["attack_successes"] / max(len(test_prompts), 1)

        self.attack_results.append(results)
        return results

    def get_attack_stats(self) -> Dict[str, Any]:
        """Get attack simulation statistics."""
        if not self.attack_results:
            return {"message": "No attack simulations run"}

        return {
            "total_simulations": len(self.attack_results),
            "avg_defense_rate": sum(r["defense_rate"] for r in self.attack_results) / len(self.attack_results),
            "by_attack_type": {
                r["attack_type"]: r["defense_rate"]
                for r in self.attack_results
            }
        }
