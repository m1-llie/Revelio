#!/usr/bin/env python3
"""Trajectory inspector for browsing agent conversation trajectories."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Static

ROLE_LABELS = {
    "assistant": "agent(Revelio)",
    "user": "user(Environment)",
    "system": "system",
    "tool": "tool(result)",
}


@dataclass
class AgentEntry:
    key: str
    agent_type: str
    hypothesis_id: str | None
    attempt: int | None
    n_steps: int
    n_calls: int
    cost: float
    exit_status: str

    @property
    def display_name(self) -> str:
        name = self.agent_type.replace("Agent", "")
        if self.hypothesis_id:
            name += f" {self.hypothesis_id}"
        if self.attempt is not None:
            name += f" #{self.attempt}"
        return name

    @property
    def status_icon(self) -> str:
        return "✓" if self.exit_status == "Submitted" else "✗"


def _parse_agent_key(key: str) -> tuple[str, str | None, int | None]:
    """Parse 'PoVBuilderAgent_H01_attempt2' into ('PoVBuilderAgent', 'H01', 2)."""
    attempt = None
    m = re.search(r"_attempt(\d+)$", key)
    if m:
        attempt = int(m.group(1))
        key = key[: m.start()]
    if "_" in key:
        base, tail = key.rsplit("_", 1)
        if re.match(r"^[A-Z]\d+$", tail):
            return base, tail, attempt
    return key, None, attempt


def _format_message_content(message: dict) -> str:
    parts = []
    content = message.get("content")
    if content:
        if isinstance(content, list):
            parts.append("\n".join(item.get("text", str(item)) for item in content))
        else:
            parts.append(str(content))
    for tc in message.get("tool_calls") or []:
        args = tc.get("arguments", {})
        args_str = "\n".join(f"  {k}: {v}" for k, v in args.items())
        parts.append(f"[Tool Call: {tc.get('name', '?')}]\n{args_str}")
    return "\n\n".join(parts) if parts else "(empty)"


def _messages_to_steps(messages: list[dict]) -> list[list[dict]]:
    """Group messages into steps: each assistant message + its follow-up responses."""
    steps: list[list[dict]] = []
    current: list[dict] = []
    for msg in messages:
        if msg.get("role") == "assistant" and current:
            steps.append(current)
            current = []
        current.append(msg)
    if current:
        steps.append(current)
    return steps


def _build_entries(agents_map: dict) -> list[AgentEntry]:
    entries = []
    for key, data in agents_map.items():
        agent_type, hyp_id, attempt = _parse_agent_key(key)
        if isinstance(data, dict):
            msgs = data.get("messages", [])
            info = data.get("info", {})
        else:
            msgs = data if isinstance(data, list) else []
            info = {}
        stats = info.get("model_stats", {})
        entries.append(
            AgentEntry(
                key=key,
                agent_type=agent_type,
                hypothesis_id=hyp_id,
                attempt=attempt,
                n_steps=len(_messages_to_steps(msgs)),
                n_calls=stats.get("api_calls", 0),
                cost=stats.get("instance_cost", 0.0),
                exit_status=info.get("exit_status", "?"),
            )
        )
    return entries


app = typer.Typer(rich_markup_mode="rich", add_completion=False)


class TrajectoryInspector(App):
    DEFAULT_CSS = """
    Screen { layout: grid; grid-size: 1; grid-rows: auto 1fr auto; }

    #main { height: 100%; layout: horizontal; }

    #sidebar {
        width: 36;
        border-right: tall $primary;
    }
    .sb-item {
        padding: 0 1;
        height: auto;
    }
    .sb-selected {
        background: $accent;
        text-style: bold;
    }
    .sb-sep {
        color: $text-muted;
        padding: 0 1;
        height: 1;
    }

    #right-panel { width: 1fr; height: 100%; }
    #info-bar {
        height: auto;
        padding: 0 2;
        background: $boost;
        text-style: bold;
        border-bottom: solid $primary;
    }
    #content-scroll { height: 1fr; }
    #content { height: auto; min-height: 0; padding: 1; }

    .msg-box {
        margin: 0 0 1 0;
        padding: 1;
        background: $surface;
        height: auto;
        width: 100%;
    }
    .msg-role {
        color: $primary;
        padding: 0 1;
        text-style: bold;
    }
    .msg-body {
        margin-top: 1;
        padding: 0 1;
    }

    Footer { dock: bottom; }
    """

    BINDINGS = [
        Binding("right,l", "next_step", "Step →", priority=True),
        Binding("left,h", "prev_step", "Step ←", priority=True),
        Binding("0", "first_step", "First", priority=True),
        Binding("$", "last_step", "Last", priority=True),
        Binding("down,j", "next_agent", "Agent ↓", priority=True),
        Binding("up,k", "prev_agent", "Agent ↑", priority=True),
        Binding("d", "scroll_down", "Scroll ↓", priority=True),
        Binding("u", "scroll_up", "Scroll ↑", priority=True),
        Binding("right_square_bracket", "next_traj", "Traj ]", priority=True),
        Binding("left_square_bracket", "prev_traj", "Traj [", priority=True),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, trajectory_files: list[Path]):
        super().__init__()
        self.trajectory_files = trajectory_files
        self._i_traj = 0
        self._i_agent = 0
        self._i_step = 0
        self.entries: list[AgentEntry] = []
        self.steps: list[list[dict]] = []
        self._agents_map: dict[str, dict] = {}
        if trajectory_files:
            self._load_trajectory()

    # ── data ──

    def _load_trajectory(self) -> None:
        try:
            data = json.loads(self.trajectory_files[self._i_traj].read_text())
            self._agents_map = data["agents"] if isinstance(data, dict) and "agents" in data else {"default": data}
            self.entries = _build_entries(self._agents_map)
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            self._agents_map = {}
            self.entries = []
            if self.is_mounted:
                self.notify(f"Load error: {e}", severity="error")
        self._i_agent = 0
        self._load_agent()

    def _load_agent(self) -> None:
        if not self.entries:
            self.steps = []
            self._i_step = 0
            return
        data = self._agents_map.get(self.entries[self._i_agent].key, {})
        msgs = data.get("messages", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        self.steps = _messages_to_steps(msgs)
        self._i_step = 0

    # ── ui ──

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            yield VerticalScroll(id="sidebar")
            with Vertical(id="right-panel"):
                yield Static(id="info-bar")
                with VerticalScroll(id="content-scroll"):
                    yield Vertical(id="content")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        self._render_sidebar()
        self._render_content()

    def _render_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", VerticalScroll)
        sidebar.remove_children()
        prev_hyp: str | None = None
        for i, e in enumerate(self.entries):
            if e.hypothesis_id and e.hypothesis_id != prev_hyp:
                prev_hyp = e.hypothesis_id
                sidebar.mount(Static(f"── {e.hypothesis_id} ──", classes="sb-sep"))
            label = f"{e.status_icon} {e.display_name}\n    {e.n_steps} steps · {e.n_calls} calls · ${e.cost:.4f}"
            classes = "sb-item sb-selected" if i == self._i_agent else "sb-item"
            sidebar.mount(Static(label, classes=classes))

    def _render_content(self) -> None:
        # info bar
        info = self.query_one("#info-bar", Static)
        if self.entries:
            e = self.entries[self._i_agent]
            info.update(f" {e.display_name}  │  {e.n_calls} calls  │  ${e.cost:.4f}  │  {e.exit_status}")
        else:
            info.update(" No agent loaded")

        # step content
        container = self.query_one("#content", Vertical)
        container.remove_children()
        if not self.steps:
            container.mount(Static("No steps"))
            self.title = "Trajectory Inspector"
            return

        for msg in self.steps[self._i_step]:
            role = msg.get("role", "unknown")
            box = Vertical(classes="msg-box")
            container.mount(box)
            box.mount(Static(ROLE_LABELS.get(role, role), classes="msg-role"))
            box.mount(Static(Text(_format_message_content(msg), no_wrap=False), classes="msg-body"))

        traj_name = self.trajectory_files[self._i_traj].parent.name
        self.title = (
            f"{traj_name}  │  "
            f"Agent {self._i_agent + 1}/{len(self.entries)}  │  "
            f"Step {self._i_step + 1}/{len(self.steps)}"
        )

    # ── navigation helpers ──

    def _goto_step(self, i: int) -> None:
        if not self.steps:
            return
        i = max(0, min(i, len(self.steps) - 1))
        if i != self._i_step:
            self._i_step = i
            self.query_one("#content-scroll", VerticalScroll).scroll_to(y=0, animate=False)
            self._render_content()

    def _goto_agent(self, i: int) -> None:
        if not self.entries:
            return
        i = max(0, min(i, len(self.entries) - 1))
        if i != self._i_agent:
            self._i_agent = i
            self._load_agent()
            self.query_one("#content-scroll", VerticalScroll).scroll_to(y=0, animate=False)
            self._refresh()

    def _goto_traj(self, i: int) -> None:
        n = len(self.trajectory_files)
        if n == 0:
            return
        i = max(0, min(i, n - 1))
        if i != self._i_traj:
            self._i_traj = i
            self._load_trajectory()
            self._refresh()

    # ── actions ──

    def action_next_step(self) -> None:
        self._goto_step(self._i_step + 1)

    def action_prev_step(self) -> None:
        self._goto_step(self._i_step - 1)

    def action_first_step(self) -> None:
        self._goto_step(0)

    def action_last_step(self) -> None:
        self._goto_step(len(self.steps) - 1)

    def action_next_agent(self) -> None:
        self._goto_agent(self._i_agent + 1)

    def action_prev_agent(self) -> None:
        self._goto_agent(self._i_agent - 1)

    def action_next_traj(self) -> None:
        self._goto_traj(self._i_traj + 1)

    def action_prev_traj(self) -> None:
        self._goto_traj(self._i_traj - 1)

    def action_scroll_down(self) -> None:
        vs = self.query_one("#content-scroll", VerticalScroll)
        vs.scroll_to(y=vs.scroll_target_y + 15)

    def action_scroll_up(self) -> None:
        vs = self.query_one("#content-scroll", VerticalScroll)
        vs.scroll_to(y=vs.scroll_target_y - 15)


@app.command(help=__doc__)
def main(
    path: str = typer.Argument(".", help="Directory or trajectory file path"),
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
        raise typer.BadParameter(f"Path '{path}' does not exist")

    TrajectoryInspector(trajectory_files).run()


if __name__ == "__main__":
    app()
