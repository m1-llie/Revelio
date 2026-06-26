"""Tool utilities for converting Python functions to LLM tool schemas."""

import inspect
import re
import types
from typing import Any, Callable, Union, get_args, get_origin, get_type_hints


def function_to_tool_schema(func: Callable) -> dict[str, Any]:
    """Convert a Python function to OpenAI-compatible tool schema.

    The function's docstring is parsed for the description and parameter docs.
    Type hints are converted to JSON schema types.
    """
    sig = inspect.signature(func)
    doc = inspect.getdoc(func) or ""
    hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}

    # Parse Args section from docstring
    param_docs = _parse_docstring_args(doc)

    # Build parameters schema
    properties: dict[str, dict] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        prop: dict[str, Any] = {"type": _python_type_to_json(hints.get(name, str))}
        if name in param_docs:
            prop["description"] = param_docs[name]
        if hints.get(name) == str and name == "status":
            prop["enum"] = ["success", "failure"]
        properties[name] = prop
        if param.default is inspect.Parameter.empty:
            required.append(name)

    return {
        "type": "function",
        "function": {
            "name": func.__name__,
            "description": doc.split("\n\n")[0].strip() if doc else "",
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def _parse_docstring_args(doc: str) -> dict[str, str]:
    """Extract parameter descriptions from docstring Args section."""
    param_docs: dict[str, str] = {}
    args_match = re.search(r"Args:\s*\n(.*?)(?:\n\s*\n|\n\s*Returns:|\Z)", doc, re.DOTALL)
    if args_match:
        for line in args_match.group(1).strip().split("\n"):
            line = line.strip()
            if ":" in line:
                name, desc = line.split(":", 1)
                param_docs[name.strip()] = desc.strip()
    return param_docs


def _python_type_to_json(py_type: type) -> str:
    """Convert Python type to JSON schema type, handling Optional/Union."""
    origin = get_origin(py_type)
    if origin is Union or isinstance(py_type, types.UnionType):
        args = [a for a in get_args(py_type) if a is not type(None)]
        if args:
            return _python_type_to_json(args[0])

    mapping = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }
    return mapping.get(py_type, "string")
