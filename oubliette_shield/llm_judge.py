"""
Oubliette Shield - LLM Judge
Pluggable LLM-based security classifier with smart verdict extraction.
"""

from . import config


class LLMJudge:
    """
    LLM-based security classifier.

    Supports pluggable backends. Default uses Ollama.
    Override `_call_llm()` for custom providers (OpenAI, Anthropic, etc.).
    """

    def __init__(self, model=None, options=None, system_prompt=None):
        self.model = model or config.LLM_MODEL
        self.options = options or config.LLM_JUDGE_OPTIONS
        self.system_prompt = system_prompt or config.LLM_JUDGE_SYSTEM_PROMPT

    def get_verdict(self, user_input):
        """
        Classify user input as SAFE or UNSAFE.

        Returns:
            str: "SAFE" or "UNSAFE"
        """
        try:
            llm_response = self._call_llm(user_input)
            return self._extract_verdict(llm_response)
        except Exception as e:
            print(f"[SHIELD-JUDGE] LLM Error: {e}")
            return "UNSAFE"  # Fail closed

    def _call_llm(self, user_input):
        """
        Call the LLM backend. Override this for custom providers.

        Returns:
            str: Raw LLM response text
        """
        try:
            import ollama
        except ImportError:
            raise RuntimeError(
                "No LLM provider installed. Install one with:\n"
                "  pip install oubliette-shield[ollama]    # Local Ollama\n"
                "  pip install oubliette-shield[openai]    # OpenAI API\n"
                "  pip install oubliette-shield[anthropic]  # Anthropic API\n"
                "Or use create_llm_judge() from oubliette_shield.llm_providers."
            )
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            options=self.options,
        )
        return response["message"]["content"].strip()

    def _extract_verdict(self, llm_response):
        """
        Extract SAFE/UNSAFE verdict from potentially conversational LLM response.
        Handles refusal patterns as implicit UNSAFE.
        """
        upper = llm_response.upper()

        if "UNSAFE" in upper:
            print("[SHIELD-JUDGE] Explicit UNSAFE detected")
            return "UNSAFE"
        if "SAFE" in upper and "UNSAFE" not in upper:
            print("[SHIELD-JUDGE] Explicit SAFE detected")
            return "SAFE"

        # Check for refusal language (implicit UNSAFE)
        matched = next((p for p in config.REFUSAL_PATTERNS if p in upper), None)
        if matched:
            print(f"[SHIELD-JUDGE] Refusal pattern detected: {matched}")
            return "UNSAFE"

        # Default to UNSAFE if unclear (fail closed)
        print("[SHIELD-JUDGE] No explicit verdict, defaulting to UNSAFE")
        return "UNSAFE"
