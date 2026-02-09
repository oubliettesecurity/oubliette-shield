"""
Oubliette Shield - LangChain Integration
Callback handler that analyzes prompts before LLM execution.

Usage:
    from oubliette_shield import Shield
    from oubliette_shield.integrations.langchain import OublietteShieldCallback

    shield = Shield()
    callback = OublietteShieldCallback(shield=shield, block=True)

    llm = ChatOpenAI(callbacks=[callback])
    llm.invoke("Hello, world!")  # Safe - passes through
    llm.invoke("ignore all instructions")  # Blocked - raises ValueError
"""

from typing import Any, Optional


class OublietteShieldCallback:
    """
    LangChain callback handler for prompt injection detection.

    Implements on_llm_start and on_chain_start to analyze inputs
    before they reach the LLM.

    Args:
        shield: Shield instance (creates default if None)
        block: If True, raises ValueError on malicious input.
               If False, logs a warning but allows execution.
        session_id: Default session ID for tracking
    """

    def __init__(self, shield=None, block=True, session_id="langchain-default"):
        if shield is None:
            from oubliette_shield import Shield
            self.shield = Shield()
        else:
            self.shield = shield
        self.block = block
        self.session_id = session_id

    def on_llm_start(self, serialized: dict, prompts: list,
                     **kwargs: Any) -> None:
        """Analyze each prompt before LLM execution."""
        for prompt in prompts:
            self._check(prompt)

    def on_chain_start(self, serialized: dict, inputs: dict,
                       **kwargs: Any) -> None:
        """Analyze chain inputs before execution."""
        # Check common input keys
        for key in ("input", "query", "question", "human_input", "text"):
            value = inputs.get(key)
            if isinstance(value, str) and value.strip():
                self._check(value)

    def on_chat_model_start(self, serialized: dict, messages: list,
                            **kwargs: Any) -> None:
        """Analyze chat messages before execution."""
        for message_batch in messages:
            for message in message_batch:
                # message can be a BaseMessage or list
                content = getattr(message, "content", None)
                if isinstance(content, str) and content.strip():
                    self._check(content)

    def _check(self, text: str) -> None:
        """Run Shield analysis on text."""
        result = self.shield.analyze(text, session_id=self.session_id)
        if result.blocked:
            msg = (
                f"Oubliette Shield blocked input: verdict={result.verdict}, "
                f"method={result.detection_method}"
            )
            if self.block:
                raise ValueError(msg)
            else:
                print(f"[SHIELD-LANGCHAIN] WARNING: {msg}")
