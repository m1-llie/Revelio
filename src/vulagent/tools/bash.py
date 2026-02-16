"""Tool for running bash command in the environment"""

import yaml


def bash(
    status: command,
    analysis: str = "",
    result_script: str = "none",
    poc: str = "none",
    report: str = "none",
    payload: dict | None = None,
) -> str:
    if status not in ("success", "failure"):
        status = "failure"
    data = {
        "status": status,
        "analysis": analysis,
        "result_script": result_script,
        "poc": poc,
        "report": report,
    }
    if payload is not None:
        data["payload"] = payload
    return yaml.dump(data, sort_keys=False)
