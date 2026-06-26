"""The finish tool for signaling task completion."""

import yaml


def finish(
    status: str,
    analysis: str = "",
    result_script: str = "none",
    poc: str = "none",
    report: str = "none",
    payload: dict | None = None,
) -> str:
    """
    Signal that the agent has finished its task. Status MUST be 'success' or 'failure'.

    'success' means the agent completed its assigned work (e.g., ran the command, produced the file). It does NOT imply a positive domain outcome (e.g., crash found). 'failure' means the agent could not complete its work at all (e.g., build broke, command not found).

    Domain-specific outcomes (crash_detected, hypothesis list, etc.) go in ``payload``.

    Args:
        status: Task completion status — 'success' (work done) or 'failure' (could not finish)
        analysis: Brief analysis of what was done and the result
        result_script: Filename of the PoC generator script, or 'none'
        poc: Filename of the PoC input file, or 'none'
        report: Filename of the vulnerability report, or 'none'
        payload: Structured payload with domain-specific results

    Returns:
        YAML string containing the task result
    """
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
