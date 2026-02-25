"""This file provides convenience functions for selecting models.
You can ignore this file completely if you explicitly set your model in your run script.
"""

import copy
import importlib
import os
import threading

from vulagent import Model


class GlobalModelStats:
    """Global model statistics tracker with optional limits."""

    def __init__(self):
        self._cost = 0.0
        self._n_calls = 0
        self._lock = threading.Lock()
        self.cost_limit = float(os.getenv("GLOBAL_COST_LIMIT", "0"))
        self.call_limit = int(os.getenv("GLOBAL_CALL_LIMIT", "0"))
        if (self.cost_limit > 0 or self.call_limit > 0) and not os.getenv("SILENT_STARTUP"):
            print(f"Global cost/call limit: ${self.cost_limit:.4f} / {self.call_limit}")

    def add(self, cost: float) -> None:
        """Add a model call with its cost, checking limits."""
        with self._lock:
            self._cost += cost
            self._n_calls += 1
        if (self.cost_limit > 0 and self._cost > self.cost_limit) or (self.call_limit > 0 and self._n_calls > self.call_limit):
            raise RuntimeError(f"Global cost/call limit exceeded: ${self._cost:.4f} / {self._n_calls}")

    @property
    def cost(self) -> float:
        return self._cost

    @property
    def n_calls(self) -> int:
        return self._n_calls


GLOBAL_MODEL_STATS = GlobalModelStats()


def get_api_keys_pool() -> list[str]:
    """Return API keys from MODEL_API_KEYS (comma-separated) or single MODEL_API_KEY."""
    pool_str = os.getenv("MODEL_API_KEYS", "")
    if pool_str:
        return [k.strip() for k in pool_str.split(",") if k.strip()]
    single = os.getenv("MODEL_API_KEY", "")
    return [single] if single else []


def get_model(input_model_name: str | None = None, config: dict | None = None) -> Model:
    """Get an initialized model object from any kind of user input or settings."""
    resolved_model_name = get_model_name(input_model_name, config)
    if config is None:
        config = {}
    config = copy.deepcopy(config)
    config["model_name"] = resolved_model_name

    model_class = get_model_class(resolved_model_name, config.pop("model_class", ""))

    if (from_env := os.getenv("MODEL_API_KEY")) and not str(type(model_class)).endswith("DeterministicModel"):
        config.setdefault("model_kwargs", {}).setdefault("api_key", from_env)

    name_lower = resolved_model_name.lower()
    is_anthropic = any(s in name_lower for s in ["anthropic", "sonnet", "opus", "claude"])
    is_gemini3 = any(s in name_lower for s in ["gemini-3", "gemini-3.0"])
    kwargs = config.setdefault("model_kwargs", {})

    if is_anthropic:
        if "set_cache_control" not in config:
            config["set_cache_control"] = "default_end"

    if is_gemini3:
        kwargs["temperature"] = 1.0

    return model_class(**config)


def get_model_name(input_model_name: str | None = None, config: dict | None = None) -> str:
    """Get a model name from any kind of user input or settings."""
    if config is None:
        config = {}
    if input_model_name:
        return input_model_name
    if from_config := config.get("model_name"):
        return from_config
    if from_env := os.getenv("MODEL_NAME"):
        return from_env
    raise ValueError("No default model set. Please run `mini-extra config setup` to set one.")


_MODEL_CLASS_MAPPING = {
    "anthropic": "vulagent.models.anthropic.AnthropicModel",
    "litellm": "vulagent.models.litellm_model.LitellmModel",
    "openrouter": "vulagent.models.openrouter_model.OpenRouterModel",
    "portkey": "vulagent.models.portkey_model.PortkeyModel",
    "deterministic": "vulagent.models.test_models.DeterministicModel",
}


def get_model_class(model_name: str, model_class: str = "") -> type:
    """Select the best model class.

    If a model_class is provided (as shortcut name, or as full import path,
    e.g., "anthropic" or "vulagent.models.anthropic.AnthropicModel"),
    it takes precedence over the `model_name`.
    Otherwise, the model_name is used to select the best model class.
    """
    if model_class:
        full_path = _MODEL_CLASS_MAPPING.get(model_class, model_class)
        try:
            module_name, class_name = full_path.rsplit(".", 1)
            module = importlib.import_module(module_name)
            return getattr(module, class_name)
        except (ValueError, ImportError, AttributeError):
            msg = f"Unknown model class: {model_class} (resolved to {full_path}, available: {_MODEL_CLASS_MAPPING})"
            raise ValueError(msg)

    # Default to LitellmModel
    from vulagent.models.litellm_model import LitellmModel

    return LitellmModel
