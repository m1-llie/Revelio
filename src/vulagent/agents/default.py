"""Basic agent class. See https://mini-swe-agent.com/latest/advanced/control_flow/ for visual explanation of the scaffold.
Changed a lot by vul-agent.

Implement the control flow:
template-driven prompting, action parsing (bash ...), command execution, termination rules, and trajectory logging.
"""

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from jinja2 import StrictUndefined, Template

from vulagent import Environment, Model
from vulagent.tools import function_to_tool_schema
from vulagent.tools.finish import finish


@dataclass
class AgentConfig:
    # The default settings are the bare minimum to run the agent. Take a look at the config files for improved settings.
    system_template: str = "You are a helpful assistant that can do anything."
    instance_template: str = (
        "Your task: {{task}}. Please reply with a single shell command in triple backticks. "
        "To finish, the first line of the output of the shell command must be 'COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT'."
    )
    timeout_template: str = (
        "The last command <command>{{action['action']}}</command> timed out and has been killed.\n"
        "The output of the command was:\n <output>\n{{output}}\n</output>\n"
        "Please try another command and make sure to avoid those requiring interactive input."
    )
    format_error_template: str = "Please always provide EXACTLY ONE action in triple backticks."
    action_observation_template: str = "Observation: {{output}}"
    step_limit: int = 0
    cost_limit: float = 3.0


class NonTerminatingException(Exception):
    """Raised for conditions that can be handled by the agent."""


class FormatError(NonTerminatingException):
    """Raised when the LM's output is not in the expected format."""


class ExecutionTimeoutError(NonTerminatingException):
    """Raised when the action execution timed out."""


class TerminatingException(Exception):
    """Raised for conditions that terminate the agent."""


class Submitted(TerminatingException):
    """Raised when the LM declares that the agent has finished its task."""


class LimitsExceeded(TerminatingException):
    """Raised when the agent has reached its cost or step limit."""


class DefaultAgent:
    def __init__(
        self,
        model: Model,
        env: Environment,
        *,
        config_class: Callable = AgentConfig,
        tools: list[Callable[..., Any]] | None = None,
        **kwargs,
    ):
        self.config = config_class(**kwargs)
        self.messages: list[dict] = []
        self.model = model
        self.env = env
        self.extra_template_vars = {}

        # Build tool map: function name -> callable
        self._tool_map: dict[str, Callable] = {f.__name__: f for f in (tools or [])}
        if "finish" not in self._tool_map:
            self._tool_map["finish"] = finish
        if "bash" not in self._tool_map:
            self._tool_map["bash"] = self._make_bash_tool()
        self._tool_schemas = [function_to_tool_schema(f) for f in self._tool_map.values()]

    def _make_bash_tool(self) -> Callable:
        """Create a bash tool function that executes commands in the environment."""
        agent = self

        def bash(command: str) -> str:
            """Execute a bash command in the environment.

            Args:
                command: The bash command to execute.
            """
            output = agent.env.execute(command)
            agent.has_finished(output)
            return agent.render_template(agent.config.action_observation_template, output=output)

        return bash

    def render_template(self, template: str, **kwargs) -> str:
        template_vars = asdict(self.config) | self.env.get_template_vars() | self.model.get_template_vars()
        return Template(template, undefined=StrictUndefined).render(
            **kwargs, **template_vars, **self.extra_template_vars
        )

    def add_message(self, role: str, content: str, **kwargs):
        timestamp = datetime.now(timezone.utc).isoformat()
        self.messages.append({"role": role, "content": content, "timestamp": timestamp, **kwargs})

    def run(self, task: str, **kwargs) -> tuple[str, str]:
        """Run step() until agent is finished. Return exit status & message"""
        self.extra_template_vars |= {"task": task, **kwargs}
        self.messages = []
        self.add_message("system", self.render_template(self.config.system_template))
        self.add_message("user", self.render_template(self.config.instance_template))
        while True:
            try:
                self.step()
            except NonTerminatingException as e:
                self.add_message("user", str(e))
            except Submitted as e:
                # Don't add redundant user message for finish tool (already in tool_calls)
                return type(e).__name__, str(e)
            except TerminatingException as e:
                self.add_message("user", str(e))
                return type(e).__name__, str(e)

    def step(self) -> dict:
        """Query the LM, execute the action, return the observation."""
        return self.get_observation(self.query())

    def query(self) -> dict:
        """Query the model and return the response."""
        if 0 < self.config.step_limit <= self.model.n_calls or 0 < self.config.cost_limit <= self.model.cost:
            raise LimitsExceeded()
        messages = [self._strip_metadata(m) for m in self.messages]
        response = self.model.query(messages, tools=self._tool_schemas)
        return response
    
    _metadata_keys = {"timestamp", "command", "command_output", "command_returncode", "tool_results", "extra"}

    @staticmethod
    def _strip_metadata(message: dict) -> dict:
        """Remove local-only metadata fields before sending messages to the model."""
        msg = {k: v for k, v in message.items() if k not in DefaultAgent._metadata_keys}
        # Convert simplified tool_calls back to OpenAI format for litellm
        if "tool_calls" in msg and msg["tool_calls"]:
            msg["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc.get("arguments", {})),
                    },
                }
                for tc in msg["tool_calls"]
            ]
        return msg

    @staticmethod
    def _is_truncated(response: dict) -> bool:
        """Check if the response was truncated due to max output tokens."""
        try:
            return response["extra"]["response"]["choices"][0]["finish_reason"] == "length"
        except (KeyError, IndexError, TypeError):
            return False

    def get_observation(self, response: dict) -> dict:
        """Execute the action (tool call or bash command) and return the observation."""
        if "tool_calls" in response and response["tool_calls"]:
            if self._is_truncated(response):
                raise FormatError(
                    "Your response was truncated due to the output token limit, "
                    "so the tool call was malformed. Please retry with a shorter response."
                )
            content = response.get("content") or ""
            if "```bash" in content:
                raise FormatError(
                    "Tool calls must not include bash blocks. Execute commands first, "
                    "then call the tool in a separate reply."
                )
            self.add_message("assistant", **response)
            return self.execute_tool_calls(response["tool_calls"])

        # Fallback: parse text-format tool calls (e.g. "Tool: bash, Arguments: {...}")
        text_call = self._parse_text_tool_call(response.get("content") or "")
        if text_call:
            self.add_message("assistant", **response)
            self.messages[-1]["tool_calls"] = [text_call]
            return self.execute_tool_calls([text_call])

        # Legacy: bash code blocks
        self.add_message("assistant", **response)
        action = self.parse_bash_action(response)
        output = self.execute_bash_action(action)
        observation = self.render_template(self.config.action_observation_template, output=output)
        self.add_message(
            "user",
            observation,
            command=action["action"],
            command_output=output.get("output", ""),
            command_returncode=output.get("returncode"),
        )
        return output

    @staticmethod
    def _parse_text_tool_call(content: str) -> dict | None:
        """Extract a tool call written as text: 'Tool: name, Arguments: {...}'."""
        m = re.search(r"Tool:\s*(\w+)\s*,\s*Arguments:\s*", content)
        if not m:
            return None
        name = m.group(1)
        rest = content[m.end():]
        if not rest.startswith("{"):
            return None
        depth = 0
        for i, ch in enumerate(rest):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if depth == 0:
                try:
                    args = json.loads(rest[: i + 1])
                    return {"name": name, "arguments": args, "id": f"text_{name}"}
                except json.JSONDecodeError:
                    return None
        return None

    def parse_bash_action(self, response: dict) -> dict:
        """Parse bash action from the message. Returns the action."""
        content = response.get("content") or ""
        actions = re.findall(r"```bash\s*\n(.*?)\n```", content, re.DOTALL)
        if len(actions) == 1:
            return {"action": actions[0].strip(), **response}
        raise FormatError(self.render_template(self.config.format_error_template, actions=actions))

    def execute_bash_action(self, action: dict) -> dict:
        """Execute a bash command in the environment."""
        try:
            output = self.env.execute(action["action"])
        except subprocess.TimeoutExpired as e:
            output = e.output.decode("utf-8", errors="replace") if e.output else ""
            raise ExecutionTimeoutError(
                self.render_template(self.config.timeout_template, action=action, output=output)
            )
        except TimeoutError:
            raise ExecutionTimeoutError(self.render_template(self.config.timeout_template, action=action, output=""))
        self.has_finished(output)
        return output

    def execute_tool_calls(self, tool_calls: list[dict]) -> dict:
        """Execute tool calls and return combined results."""
        results = []
        for call in tool_calls:
            name = call["name"]
            arguments = call.get("arguments", {})
            tool_call_id = call.get("id", name)

            if name not in self._tool_map:
                result = f"Error: Unknown tool '{name}'"
            else:
                try:
                    result = self._tool_map[name](**arguments)
                except TypeError as e:
                    result = f"Error calling tool '{name}': {e}"

            # For finish tool, raise Submitted with the result
            if name == "finish":
                raise Submitted(result)

            results.append({"tool_call_id": tool_call_id, "name": name, "result": result})

        # Add one tool-result message per call (required by Anthropic/litellm API)
        for r in results:
            self.add_message("tool", content=r["result"], tool_call_id=r["tool_call_id"], tool_results=results)
        return {"output": results[0]["result"] if results else "", "returncode": 0}

    def has_finished(self, output: dict[str, str]):
        """Raises Submitted exception with final output if the agent has finished its task (legacy support)."""
        lines = output.get("output", "").lstrip().splitlines(keepends=True)
        if lines and lines[0].strip() in ["MINI_SWE_AGENT_FINAL_OUTPUT", "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"]:
            raise Submitted("".join(lines[1:]))
