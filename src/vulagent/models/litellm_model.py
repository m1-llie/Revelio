import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import litellm
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_not_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from vulagent.models import GLOBAL_MODEL_STATS
from vulagent.models.utils.cache_control import set_cache_control

logger = logging.getLogger("litellm_model")


def _parse_tool_calls(message) -> list[dict] | None:
    """Parse tool calls from LLM response message."""
    if not hasattr(message, "tool_calls") or not message.tool_calls:
        return None
    return [
        {
            "id": tc.id,
            "name": tc.function.name,
            "arguments": json.loads(tc.function.arguments) if tc.function.arguments else {},
        }
        for tc in message.tool_calls
    ]


@dataclass
class LitellmModelConfig:
    model_name: str
    model_kwargs: dict[str, Any] = field(default_factory=dict)
    litellm_model_registry: Path | str | None = os.getenv("LITELLM_MODEL_REGISTRY_PATH")
    set_cache_control: Literal["default_end"] | None = None
    """Set explicit cache control markers, for example for Anthropic models"""


class LitellmModel:
    def __init__(self, *, config_class: type = LitellmModelConfig, **kwargs):
        self.config = config_class(**kwargs)
        self.cost = 0.0
        self.n_calls = 0
        if self.config.litellm_model_registry and Path(self.config.litellm_model_registry).is_file():
            litellm.utils.register_model(json.loads(Path(self.config.litellm_model_registry).read_text()))

    @retry(
        stop=stop_after_attempt(int(os.getenv("MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT", "10"))),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry=retry_if_not_exception_type(
            (
                litellm.exceptions.UnsupportedParamsError,
                litellm.exceptions.BadRequestError,
                litellm.exceptions.NotFoundError,
                litellm.exceptions.PermissionDeniedError,
                litellm.exceptions.ContextWindowExceededError,
                litellm.exceptions.APIError,
                litellm.exceptions.AuthenticationError,
                KeyboardInterrupt,
            )
        ),
    )
    def _query(self, messages: list[dict[str, str]], **kwargs):
        try:
            return litellm.completion(
                model=self.config.model_name, messages=messages, **(self.config.model_kwargs | kwargs)
            )
        except litellm.exceptions.AuthenticationError as e:
            e.message += " You can permanently set your API key with `mini-extra config set KEY VALUE`."
            raise e

    def query(self, messages: list[dict[str, str]], tools: list[dict] | None = None, **kwargs) -> dict:
        if self.config.set_cache_control:
            messages = set_cache_control(messages, mode=self.config.set_cache_control)
        if tools:
            kwargs["tools"] = tools
        response = self._query(messages, **kwargs)
        try:
            cost = litellm.cost_calculator.completion_cost(response)
        except Exception as e:
            logger.critical(
                f"Error calculating cost for model {self.config.model_name}: {e}. "
                "Please check the 'Updating the model registry' section in the documentation at "
                "https://klieret.short.gy/litellm-model-registry Still stuck? Please open a github issue for help!"
            )
            raise
        self.n_calls += 1
        assert cost >= 0.0, f"Cost is negative: {cost}"
        self.cost += cost
        GLOBAL_MODEL_STATS.add(cost)

        if not response.choices:
            logger.warning(
                "Model returned empty choices (likely safety filter). "
                "Returning empty content so the agent loop can retry."
            )
            return {"content": "[Model returned no response — possibly blocked by safety filter. Please try a different approach.]"}

        msg = response.choices[0].message
        result: dict[str, Any] = {
            "content": msg.content or "",
            "extra": {"response": response.model_dump()},
        }

        tool_calls = _parse_tool_calls(msg)
        if tool_calls:
            result["tool_calls"] = tool_calls

        return result

    def get_template_vars(self) -> dict[str, Any]:
        return asdict(self.config) | {"n_model_calls": self.n_calls, "model_cost": self.cost}
