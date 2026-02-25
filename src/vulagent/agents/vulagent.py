"""
Implement the control flow:
template-driven prompting, action parsing (bash ...), command execution, termination rules, and trajectory logging.
"""

from pathlib import Path
from .default import DefaultAgent

class VulAgent(DefaultAgent):
    def __init__(self, log_path: Path, console, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert not log_path.exists(), f"you are erasing an existing log: {log_path}"
        self.log_path = log_path
        self.log_handle = open(log_path, "w")
        self.console = console
        self.step_cnt = 0

    def add_message(self, role: str, content: str, **kwargs):
        self.log_handle.write("\n" + ">"*20 + f" {role}\n" + content)
        self.log_handle.flush()
        return super().add_message(role, content, **kwargs)

    def step(self):
        self.step_cnt += 1
        self.console.print(f"[dim]Step {self.step_cnt}: querying/executing...[/dim]")
        return super().step()

    def run(self, *args, **kwargs):
        ret = super().run(*args, **kwargs)
        self.log_handle.close() 
        return ret

