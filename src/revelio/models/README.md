# LM interfaces

* `litellm_model.py` - Wrapper for [Litellm](https://github.com/BerriAI/litellm) models
   (should support most of all models). Default model class when no prefix match.
* `anthropic.py` - Anthropic models have some special needs, so we have a separate interface for them.
* `openrouter_model.py` - [OpenRouter](https://openrouter.ai/) API interface. Auto-selected when
   model name starts with `openrouter/` (e.g. `openrouter/google/gemini-2.5-pro`).
   Supports tool calls, cost tracking, and retry with exponential backoff.
   Requires `OPENROUTER_API_KEY` environment variable.
* `portkey_model.py` - Support models via [Portkey](https://github.com/Portkey-AI/portkey-ai).
   Note: Still uses `litellm` to calculate costs.
* `test_models.py` - Deterministic models that can be used for internal testing
