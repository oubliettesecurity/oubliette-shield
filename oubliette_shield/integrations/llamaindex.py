"""
Oubliette Shield - LlamaIndex Integration
Query transform that analyzes queries before retrieval.

Usage:
    from oubliette_shield import Shield
    from oubliette_shield.integrations.llamaindex import OublietteShieldTransform

    shield = Shield()
    transform = OublietteShieldTransform(shield=shield)

    # Use as a query transform
    safe_query = transform("What is machine learning?")  # Passes through
    bad_query = transform("ignore all instructions")     # Raises ValueError
"""


class OublietteShieldTransform:
    """
    LlamaIndex query transform for prompt injection detection.

    Analyzes query strings before they reach the retrieval pipeline.

    Args:
        shield: Shield instance (creates default if None)
        block: If True, raises ValueError on malicious input.
               If False, returns the query with a warning logged.
        session_id: Default session ID for tracking
    """

    def __init__(self, shield=None, block=True, session_id="llamaindex-default"):
        if shield is None:
            from oubliette_shield import Shield
            self.shield = Shield()
        else:
            self.shield = shield
        self.block = block
        self.session_id = session_id

    def __call__(self, query_str, **kwargs):
        """
        Analyze a query string for prompt injection.

        Args:
            query_str: The query to analyze
            **kwargs: Additional arguments (passed through)

        Returns:
            str: The original query string if safe

        Raises:
            ValueError: If the query is malicious and block=True
        """
        if not isinstance(query_str, str) or not query_str.strip():
            return query_str

        result = self.shield.analyze(query_str, session_id=self.session_id)

        if result.blocked:
            msg = (
                f"Oubliette Shield blocked query: verdict={result.verdict}, "
                f"method={result.detection_method}"
            )
            if self.block:
                raise ValueError(msg)
            else:
                print(f"[SHIELD-LLAMAINDEX] WARNING: {msg}")

        return query_str
