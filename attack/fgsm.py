"""
FGSM (Fast Gradient Sign Method) Attack Implementation
Reference: Goodfellow et al., "Explaining and Harnessing Adversarial Examples", ICLR 2015
"""
import numpy as np
from typing import Callable, List, Dict, Any


class FGSMAttack:
    """
    Fast Gradient Sign Method attack for text/LLM models.

    This attack computes the gradient of the loss w.r.t. input tokens
    and perturbs the input in the direction that maximizes loss.
    """

    def __init__(self, epsilon: float = 0.1, targeted: bool = False):
        """
        Args:
            epsilon: Perturbation magnitude
            targeted: Whether to use targeted attack
        """
        self.epsilon = epsilon
        self.targeted = targeted

    def generate(self, text: str, model, tokenizer, target: str = None) -> str:
        """
        Generate adversarial text using FGSM.

        Args:
            text: Original input text
            model: Target language model
            tokenizer: Tokenizer for the model
            target: Target response (for targeted attacks)

        Returns:
            Adversarial text
        """
        # Tokenize input
        tokens = tokenizer.encode(text, return_tensors="pt")

        # For text, we simulate gradient-based perturbation
        # by synonym replacement or character-level modification
        words = text.split()
        perturbed_words = words.copy()

        # Simple gradient approximation: perturb words that might trigger safety
        for i, word in enumerate(perturbed_words):
            if self._is_suspicious_word(word):
                # Add subtle perturbation
                perturbed_words[i] = self._perturb_word(word)

        return " ".join(perturbed_words)

    def _is_suspicious_word(self, word: str) -> bool:
        """Check if word might be a safety-related keyword."""
        safety_keywords = ["safe", "block", "prevent", "restrict", "cannot", "will not"]
        return any(kw in word.lower() for kw in safety_keywords)

    def _perturb_word(self, word: str) -> str:
        """Apply subtle perturbation to a word."""
        # Character-level perturbation (case swap, char repeat, etc.)
        if len(word) > 2:
            # Swap inner characters
            chars = list(word)
            if len(chars) > 2:
                chars[1], chars[-1] = chars[-1], chars[1]
            return "".join(chars)
        return word

    def attack_batch(self, texts: List[str], model, tokenizer) -> List[str]:
        """Attack multiple texts."""
        return [self.generate(text, model, tokenizer) for text in texts]


class TextFGSM:
    """Alternative FGSM implementation with embedding perturbation."""

    def __init__(self, epsilon: float = 0.25):
        self.epsilon = epsilon

    def craft_adversarial_example(
        self,
        text: str,
        loss_fn: Callable,
        model,
        tokenizer
    ) -> Dict[str, Any]:
        """
        Craft adversarial example by perturbing embeddings.

        Args:
            text: Input text
            loss_fn: Loss function for gradient computation
            model: Target model
            tokenizer: Tokenizer

        Returns:
            Dict containing adversarial text and metadata
        """
        inputs = tokenizer(text, return_tensors="pt")

        # Note: In practice, this requires differentiable model
        # For demonstration, we use heuristic perturbation
        adv_text = self._heuristic_perturb(text)

        return {
            "original_text": text,
            "adversarial_text": adv_text,
            "epsilon": self.epsilon,
            "attack_type": "FGSM"
        }

    def _heuristic_perturb(self, text: str) -> str:
        """Heuristic perturbation based on common attack patterns."""
        # Common patterns for LLM jailbreak
        replacements = [
            ("ignore", "ign0re"),
            ("previous", "pr3vious"),
            ("instructions", "1nstructions"),
            ("system", "5y5tem"),
            ("response", "r35pons3"),
        ]

        result = text
        for old, new in replacements:
            result = result.lower().replace(old, new)

        return result
