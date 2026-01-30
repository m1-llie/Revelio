"""The finish tool for signaling task completion."""

import yaml


def finish(
    status: str,
    analysis: str = "",
    result_script: str = "none",
    poc: str = "none",
    report: str = "none",
) -> str:
    """
    Call this tool when the task is complete. Status MUST be 'success' or 'failure'.

    Args:
        status: Task outcome, must be 'success' or 'failure'
        analysis: Brief analysis of what was attempted and why it succeeded/failed
        result_script: Filename of the Python script that generates the PoC, or 'none' if failure
        poc: Filename of the PoC input file, or 'none' if failure
        report: Filename of the vulnerability report, or 'none' if failure

    Returns:
        YAML string containing the task result
    """
    if status not in ("success", "failure"):
        status = "failure"
    return yaml.dump(
        {
            "status": status,
            "analysis": analysis,
            "result_script": result_script,
            "poc": poc,
            "report": report,
        },
        sort_keys=False,
    )
