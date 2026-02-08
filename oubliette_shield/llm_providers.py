"""
Oubliette Shield - Cloud LLM Provider Adapters
================================================
Pluggable LLM backends for the security classifier and chat completion.

Supported providers:
    - ollama (default): Local Ollama with llama3, mistral, phi3, gemma2, qwen2.5
    - openai: OpenAI GPT-4o / GPT-4o-mini
    - anthropic: Anthropic Claude Sonnet / Haiku
    - azure: Azure OpenAI Service
    - bedrock: AWS Bedrock (Claude, Titan, Llama)
    - vertex: Google Vertex AI (Gemini)
    - gemini: Google Gemini API (direct)

Usage:
    from oubliette_shield.llm_providers import create_llm_judge, chat_completion

    # Create a judge using env vars
    judge = create_llm_judge()

    # Or specify provider explicitly
    judge = create_llm_judge("openai", api_key="sk-...")

    # Simple chat completion (for decoy/assistant responses)
    response = chat_completion(
        messages=[{"role": "user", "content": "Hello"}],
        system="You are a helpful assistant.",
    )
"""

import os
from .llm_judge import LLMJudge
from . import config


# ============================================================================
# Provider: Ollama (default, local)
# ============================================================================
# Supported local models via Ollama:
#   llama3     - Meta Llama 3 8B (default, balanced performance)
#   mistral    - Mistral 7B (strong instruction following)
#   phi3       - Microsoft Phi-3 (small, very fast, good for constrained envs)
#   gemma2     - Google Gemma 2 (good reasoning, larger context)
#   qwen2.5    - Alibaba Qwen 2.5 (strong multilingual support)
# Select via SHIELD_LLM_MODEL env var (default: llama3)

class OllamaJudge(LLMJudge):
    """Explicit Ollama judge (same as base LLMJudge, for clarity)."""

    def __init__(self, model=None, **kwargs):
        super().__init__(model=model, **kwargs)

    def _call_llm(self, user_input):
        import ollama
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            options=self.options,
        )
        return response["message"]["content"].strip()


# ============================================================================
# Provider: OpenAI
# ============================================================================

class OpenAIJudge(LLMJudge):
    """OpenAI GPT-based judge. Requires: pip install openai"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gpt-4o-mini")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY env var.")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package required. Install with: pip install openai>=1.0.0"
                )
            self._client = openai.OpenAI(api_key=self.api_key)
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            max_tokens=10,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


# ============================================================================
# Provider: Anthropic
# ============================================================================

class AnthropicJudge(LLMJudge):
    """Anthropic Claude judge. Requires: pip install anthropic"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "claude-sonnet-4-5-20250929")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var.")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "anthropic package required. Install with: pip install anthropic>=0.40.0"
                )
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=10,
            system=self.system_prompt,
            messages=[
                {"role": "user", "content": user_input},
            ],
        )
        return response.content[0].text.strip()


# ============================================================================
# Provider: Azure OpenAI
# ============================================================================

class AzureOpenAIJudge(LLMJudge):
    """Azure OpenAI judge. Requires: pip install openai"""

    def __init__(self, model=None, endpoint=None, api_key=None,
                 deployment=None, api_version=None, **kwargs):
        super().__init__(model=model or "gpt-4o-mini", **kwargs)
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.api_key = api_key or os.getenv("AZURE_OPENAI_KEY", "")
        self.deployment = deployment or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        self.api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if not self.endpoint or not self.api_key or not self.deployment:
            raise ValueError(
                "Azure OpenAI requires AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY, "
                "and AZURE_OPENAI_DEPLOYMENT env vars."
            )
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package required. Install with: pip install openai>=1.0.0"
                )
            self._client = openai.AzureOpenAI(
                azure_endpoint=self.endpoint,
                api_key=self.api_key,
                api_version=self.api_version,
            )
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            max_tokens=10,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


# ============================================================================
# Provider: AWS Bedrock
# ============================================================================

class BedrockJudge(LLMJudge):
    """AWS Bedrock judge. Requires: pip install boto3"""

    def __init__(self, model=None, region=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0")
        super().__init__(model=model or default_model, **kwargs)
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 package required. Install with: pip install boto3>=1.34.0"
                )
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
            )
        return self._client

    def _call_llm(self, user_input):
        import json
        client = self._get_client()

        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 10,
            "system": self.system_prompt,
            "messages": [
                {"role": "user", "content": user_input},
            ],
        })

        response = client.invoke_model(
            modelId=self.model,
            body=body,
            contentType="application/json",
            accept="application/json",
        )

        result = json.loads(response["body"].read())
        return result["content"][0]["text"].strip()


# ============================================================================
# Provider: Google Vertex AI
# ============================================================================

class VertexAIJudge(LLMJudge):
    """Google Vertex AI judge. Requires: pip install google-cloud-aiplatform"""

    def __init__(self, model=None, project=None, location=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gemini-2.0-flash")
        super().__init__(model=model or default_model, **kwargs)
        self.project = project or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        self.location = location or os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        if not self.project:
            raise ValueError("Vertex AI requires GOOGLE_CLOUD_PROJECT env var.")
        self._model_instance = None

    def _get_model(self):
        if self._model_instance is None:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel
            except ImportError:
                raise ImportError(
                    "google-cloud-aiplatform required. "
                    "Install with: pip install google-cloud-aiplatform>=1.40.0"
                )
            vertexai.init(project=self.project, location=self.location)
            self._model_instance = GenerativeModel(
                self.model,
                system_instruction=self.system_prompt,
            )
        return self._model_instance

    def _call_llm(self, user_input):
        model = self._get_model()
        response = model.generate_content(
            user_input,
            generation_config={"max_output_tokens": 10, "temperature": 0.1},
        )
        return response.text.strip()


# ============================================================================
# Provider: Google Gemini (direct API)
# ============================================================================

class GeminiJudge(LLMJudge):
    """Google Gemini API judge. Requires: pip install google-generativeai"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gemini-2.0-flash")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY", "")
        if not self.api_key:
            raise ValueError("Google API key required. Set GOOGLE_API_KEY env var.")
        self._model_instance = None

    def _get_model(self):
        if self._model_instance is None:
            try:
                import google.generativeai as genai
            except ImportError:
                raise ImportError(
                    "google-generativeai required. "
                    "Install with: pip install google-generativeai>=0.8.0"
                )
            genai.configure(api_key=self.api_key)
            self._model_instance = genai.GenerativeModel(
                self.model,
                system_instruction=self.system_prompt,
            )
        return self._model_instance

    def _call_llm(self, user_input):
        model = self._get_model()
        response = model.generate_content(
            user_input,
            generation_config={"max_output_tokens": 10, "temperature": 0.1},
        )
        return response.text.strip()


# ============================================================================
# Factory
# ============================================================================

_PROVIDERS = {
    "ollama": OllamaJudge,
    "openai": OpenAIJudge,
    "anthropic": AnthropicJudge,
    "azure": AzureOpenAIJudge,
    "bedrock": BedrockJudge,
    "vertex": VertexAIJudge,
    "gemini": GeminiJudge,
}


def create_llm_judge(provider=None, **kwargs):
    """
    Factory: create an LLM judge for the configured provider.

    Args:
        provider: Provider name (ollama, openai, anthropic, azure, bedrock, vertex, gemini).
                  Defaults to SHIELD_LLM_PROVIDER env var or "ollama".
        **kwargs: Provider-specific arguments (api_key, endpoint, etc.)

    Returns:
        LLMJudge subclass instance

    Raises:
        ValueError: If provider is unknown
    """
    provider = provider or os.getenv("SHIELD_LLM_PROVIDER", "ollama")
    provider = provider.lower().strip()

    cls = _PROVIDERS.get(provider)
    if cls is None:
        available = ", ".join(sorted(_PROVIDERS.keys()))
        raise ValueError(
            f"Unknown LLM provider: '{provider}'. Available: {available}"
        )

    print(f"[SHIELD-LLM] Initializing provider: {provider}")
    return cls(**kwargs)


# ============================================================================
# Chat Completion Helper (for decoy/assistant responses)
# ============================================================================

def chat_completion(messages, system=None, options=None, **kwargs):
    """
    Provider-agnostic chat completion for general conversation.

    Uses the configured SHIELD_LLM_PROVIDER to generate responses.
    This replaces direct ollama.chat() calls in oubliette_security.py.

    Args:
        messages: List of {"role": ..., "content": ...} dicts
        system: Optional system prompt (prepended to messages)
        options: Provider-specific options (Ollama options dict, etc.)
        **kwargs: Additional provider-specific arguments

    Returns:
        str: The assistant's response text
    """
    provider = os.getenv("SHIELD_LLM_PROVIDER", "ollama").lower().strip()
    model = os.getenv("SHIELD_LLM_MODEL", "llama3")

    # Build full message list with system prompt
    full_messages = []
    if system and provider in ("ollama", "openai", "azure"):
        full_messages.append({"role": "system", "content": system})
    full_messages.extend(messages)

    if provider == "ollama":
        return _chat_ollama(full_messages, model, options)
    elif provider == "openai":
        return _chat_openai(full_messages, model, kwargs.get("api_key"))
    elif provider == "anthropic":
        return _chat_anthropic(full_messages, model, system, kwargs.get("api_key"))
    elif provider == "azure":
        return _chat_azure(full_messages, kwargs)
    elif provider == "bedrock":
        return _chat_bedrock(full_messages, model, system, kwargs)
    elif provider in ("vertex", "gemini"):
        return _chat_gemini(full_messages, model, system, provider, kwargs)
    else:
        # Fallback to Ollama
        return _chat_ollama(full_messages, model, options)


def _chat_ollama(messages, model, options=None):
    """Ollama chat completion."""
    import ollama
    default_options = {
        "num_ctx": 1024,
        "num_predict": 200,
        "temperature": 0.7,
        "top_k": 40,
        "top_p": 0.9,
    }
    if options:
        default_options.update(options)
    response = ollama.chat(model=model, messages=messages, options=default_options)
    return response["message"]["content"]


def _chat_openai(messages, model, api_key=None):
    """OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY", ""))
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_anthropic(messages, model, system=None, api_key=None):
    """Anthropic chat completion."""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required. Install with: pip install anthropic>=0.40.0")
    client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""))
    # Filter out system messages (Anthropic uses separate system param)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    response = client.messages.create(
        model=model,
        max_tokens=200,
        system=sys_prompt,
        messages=user_messages,
    )
    return response.content[0].text


def _chat_azure(messages, kwargs):
    """Azure OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.AzureOpenAI(
        azure_endpoint=kwargs.get("endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT", ""),
        api_key=kwargs.get("api_key") or os.getenv("AZURE_OPENAI_KEY", ""),
        api_version=kwargs.get("api_version") or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
    )
    deployment = kwargs.get("deployment") or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
    response = client.chat.completions.create(
        model=deployment,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_bedrock(messages, model, system=None, kwargs=None):
    """AWS Bedrock chat completion."""
    import json
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 package required. Install with: pip install boto3>=1.34.0")
    kwargs = kwargs or {}
    region = kwargs.get("region") or os.getenv("AWS_REGION", "us-east-1")
    client = boto3.client("bedrock-runtime", region_name=region)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 200,
        "system": sys_prompt,
        "messages": user_messages,
    })
    response = client.invoke_model(
        modelId=model, body=body,
        contentType="application/json", accept="application/json",
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def _chat_gemini(messages, model, system=None, provider="gemini", kwargs=None):
    """Google Gemini/Vertex chat completion."""
    kwargs = kwargs or {}
    if provider == "vertex":
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
        except ImportError:
            raise ImportError("google-cloud-aiplatform required.")
        project = kwargs.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        location = kwargs.get("location") or os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        vertexai.init(project=project, location=location)
        gen_model = GenerativeModel(model, system_instruction=system or "")
    else:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("google-generativeai required.")
        genai.configure(api_key=kwargs.get("api_key") or os.getenv("GOOGLE_API_KEY", ""))
        gen_model = genai.GenerativeModel(model, system_instruction=system or "")

    # Combine user messages into a single prompt for Gemini
    user_text = "\n".join(m["content"] for m in messages if m["role"] != "system")
    response = gen_model.generate_content(
        user_text,
        generation_config={"max_output_tokens": 200, "temperature": 0.7},
    )
    return response.text
