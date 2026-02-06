#!/usr/bin/env python3
"""
Simple trajectory inspector for browsing agent conversation trajectories.
"""

import json
import os
from pathlib import Path

import typer
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Static

ASSISTANT_DISPLAY_NAME = "assistant(Vul-Agent)"
USER_DISPLAY_NAME = "user(Environment)"


def _format_message_content(message: dict) -> str:
    """Format message content, including tool calls if present."""
    parts = []

    # Regular content
    content = message.get("content")
    if content:
        if isinstance(content, list):
            parts.append("\n".join([item.get("text", str(item)) for item in content]))
        else:
            parts.append(str(content))

    # Tool calls (for assistant messages)
    tool_calls = message.get("tool_calls")
    if tool_calls:
        for tc in tool_calls:
            name = tc.get("name", "unknown")
            args = tc.get("arguments", {})
            args_str = "\n".join(f"  {k}: {v}" for k, v in args.items())
            parts.append(f"[Tool Call: {name}]\n{args_str}")

    return "\n\n".join(parts) if parts else "(empty)"


def _messages_to_steps(messages: list[dict]) -> list[list[dict]]:
    """Convert a list of messages into steps (grouped by assistant/user pairs)."""
    steps = []
    current_step = []
    for message in messages:
        current_step.append(message)
        if message.get("role") == "user" and len(current_step) > 1:
            steps.append(current_step)
            current_step = []
    if current_step:
        steps.append(current_step)
    return steps

app = typer.Typer(rich_markup_mode="rich", add_completion=False)


class TrajectoryInspector(App):
    BINDINGS = [
        Binding("right,l", "next_step", "Step++"),
        Binding("left,h", "previous_step", "Step--"),
        Binding("0", "first_step", "Step=0"),
        Binding("$", "last_step", "Step=-1"),
        Binding("j,down", "scroll_down", "Scroll down"),
        Binding("k,up", "scroll_up", "Scroll up"),
        Binding("L", "next_trajectory", "Next trajectory"),
        Binding("H", "previous_trajectory", "Previous trajectory"),
        Binding("n", "next_agent", "Agent++"),
        Binding("p", "previous_agent", "Agent--"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, trajectory_files: list[Path]):
        css_path = os.environ.get(
            "MSWEA_INSPECTOR_STYLE_PATH", str(Path(__file__).parent.parent / "config" / "mini.tcss")
        )
        self.__class__.CSS = Path(css_path).read_text()

        super().__init__()
        self.trajectory_files = trajectory_files
        self._i_trajectory = 0
        self._i_step = 0
        self._i_agent = 0
        self.messages = []
        self.steps = []
        self.agent_names: list[str] = []
        self._agents_map: dict[str, dict] = {}

        if trajectory_files:
            self._load_current_trajectory()

    # --- Basics ---

    @property
    def i_step(self) -> int:
        """Current step index."""
        return self._i_step

    @i_step.setter
    def i_step(self, value: int) -> None:
        """Set current step index, automatically clamping to valid bounds."""
        if value != self._i_step and self.n_steps > 0:
            self._i_step = max(0, min(value, self.n_steps - 1))
            self.query_one(VerticalScroll).scroll_to(y=0, animate=False)
            self.update_content()

    @property
    def n_steps(self) -> int:
        """Number of steps in current trajectory."""
        return len(self.steps)

    @property
    def i_agent(self) -> int:
        """Current agent index."""
        return self._i_agent

    @i_agent.setter
    def i_agent(self, value: int) -> None:
        if value != self._i_agent and self.n_agents > 0:
            self._i_agent = max(0, min(value, self.n_agents - 1))
            self._load_agent()
            self.query_one(VerticalScroll).scroll_to(y=0, animate=False)
            self.update_content()

    @property
    def n_agents(self) -> int:
        """Number of agents in current trajectory."""
        return len(self.agent_names)

    @property
    def i_trajectory(self) -> int:
        """Current trajectory index."""
        return self._i_trajectory

    @i_trajectory.setter
    def i_trajectory(self, value: int) -> None:
        """Set current trajectory index, automatically clamping to valid bounds."""
        if value != self._i_trajectory and self.n_trajectories > 0:
            self._i_trajectory = max(0, min(value, self.n_trajectories - 1))
            self._load_current_trajectory()
            self.query_one(VerticalScroll).scroll_to(y=0, animate=False)
            self.update_content()

    @property
    def n_trajectories(self) -> int:
        """Number of trajectory files."""
        return len(self.trajectory_files)

    def _load_current_trajectory(self) -> None:
        """Load the currently selected trajectory file."""
        if not self.trajectory_files:
            self.messages = []
            self.steps = []
            self.agent_names = []
            self._agents_map = {}
            return

        trajectory_file = self.trajectory_files[self.i_trajectory]
        try:
            data = json.loads(trajectory_file.read_text())

            self.agent_names = []
            self._agents_map = {}

            if isinstance(data, dict) and "agents" in data and isinstance(data["agents"], dict):
                self._agents_map = data["agents"]
                self.agent_names = list(self._agents_map.keys())
            else:
                self._agents_map = {"default": data}
                self.agent_names = ["default"]

            self._i_agent = 0
            self._load_agent()
        except (json.JSONDecodeError, FileNotFoundError, ValueError) as e:
            self.messages = []
            self.steps = []
            self.agent_names = []
            self._agents_map = {}
            self.notify(f"Error loading {trajectory_file.name}: {e}", severity="error")

    def _load_agent(self) -> None:
        """Load messages and steps for the current agent."""
        if not self.agent_names:
            self.messages = []
            self.steps = []
            return
        agent_name = self.agent_names[self.i_agent]
        data = self._agents_map.get(agent_name, {})

        if isinstance(data, list):
            self.messages = data
        elif isinstance(data, dict) and "messages" in data:
            self.messages = data["messages"]
        else:
            self.messages = []

        self.steps = _messages_to_steps(self.messages)
        self._i_step = 0

    @property
    def current_trajectory_name(self) -> str:
        """Get the name of the current trajectory file."""
        if not self.trajectory_files:
            return "No trajectories"
        return self.trajectory_files[self.i_trajectory].name

    @property
    def current_agent_name(self) -> str:
        if not self.agent_names:
            return "No agent"
        return self.agent_names[self.i_agent]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with VerticalScroll():
                yield Vertical(id="content")
        yield Footer()

    def on_mount(self) -> None:
        self.update_content()

    def update_content(self) -> None:
        """Update the displayed content."""
        container = self.query_one("#content", Vertical)
        container.remove_children()

        if not self.steps:
            container.mount(Static("No trajectory loaded or empty trajectory"))
            self.title = "Trajectory Inspector - No Data"
            return

        for message in self.steps[self.i_step]:
            content_str = _format_message_content(message)
            message_container = Vertical(classes="message-container")
            container.mount(message_container)
            role = message.get("role", "")
            if role == "assistant":
                role_display = ASSISTANT_DISPLAY_NAME
            elif role == "user":
                role_display = USER_DISPLAY_NAME
            elif role == "system":
                role_display = "system"
            elif role == "tool":
                role_display = "tool(result)"
            else:
                role_display = role or "unknown"
            message_container.mount(Static(role_display, classes="message-header"))
            message_container.mount(Static(Text(content_str, no_wrap=False), classes="message-content"))

        self.title = (
            f"Trajectory {self.i_trajectory + 1}/{self.n_trajectories} - "
            f"{self.current_trajectory_name} - "
            f"Agent {self.current_agent_name} ({self.i_agent + 1}/{self.n_agents}) - "
            f"Step {self.i_step + 1}/{self.n_steps}"
        )

    # --- Navigation actions ---

    def action_next_step(self) -> None:
        self.i_step += 1

    def action_previous_step(self) -> None:
        self.i_step -= 1

    def action_first_step(self) -> None:
        self.i_step = 0

    def action_last_step(self) -> None:
        self.i_step = self.n_steps - 1

    def action_next_trajectory(self) -> None:
        self.i_trajectory += 1

    def action_previous_trajectory(self) -> None:
        self.i_trajectory -= 1

    def action_next_agent(self) -> None:
        self.i_agent += 1

    def action_previous_agent(self) -> None:
        self.i_agent -= 1

    def action_scroll_down(self) -> None:
        vs = self.query_one(VerticalScroll)
        vs.scroll_to(y=vs.scroll_target_y + 15)

    def action_scroll_up(self) -> None:
        vs = self.query_one(VerticalScroll)
        vs.scroll_to(y=vs.scroll_target_y - 15)


@app.command(help=__doc__)
def main(
    path: str = typer.Argument(".", help="Directory to search for trajectory files or specific trajectory file"),
) -> None:
    path_obj = Path(path)

    if path_obj.is_file():
        trajectory_files = [path_obj]
    elif path_obj.is_dir():
        files = list(path_obj.rglob("trajectory.json"))
        files += list(path_obj.rglob("*.traj.json"))
        trajectory_files = sorted(set(files))
        if not trajectory_files:
            raise typer.BadParameter(f"No trajectory files found in '{path}'")
    else:
        raise typer.BadParameter(f"Error: Path '{path}' does not exist")

    inspector = TrajectoryInspector(trajectory_files)
    inspector.run()


if __name__ == "__main__":
    app()
