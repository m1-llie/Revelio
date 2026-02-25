import os
from pathlib import Path

import typer
import yaml
from rich.console import Console

from vulagent import package_dir
from vulagent.agents.default import DefaultAgent
from vulagent.environments.local import LocalEnvironment
from vulagent.models.litellm_model import LitellmModel
from vulagent.run.utils.save import save_traj
from vulagent.utils.log import logger

app = typer.Typer()
console = Console()


@app.command()
def main(
    task: str = typer.Option(..., "-t", "--task", help="Task/problem statement", show_default=False, prompt=True),
    model_name: str = typer.Option(
        os.getenv("MODEL_NAME"),
        "--model",
        help="Model name (defaults to MODEL_NAME env var). Can be empty if MODEL_NAME is set.",
        prompt="What model do you want to use? (press Enter to use default from .env)",
    ),
    output: Path = typer.Option(
        None,
        "-o",
        "--output",
        help="Save trajectory to this file (default: hello_world_traj.json)",
    ),
) -> DefaultAgent:
    """Run vul-agent with a simple task."""
    # Handle empty model_name
    if not model_name or model_name.strip() == "":
        model_name = os.getenv("MODEL_NAME")
        if not model_name:
            console.print("[bold red]Error:[/bold red] No model specified. Please set MODEL_NAME in .env or use -m option.")
            raise typer.Exit(1)
        console.print(f"[dim]Using model from .env: {model_name}[/dim]")
    else:
        console.print(f"[bold green]Using model:[/bold green] {model_name}")
    
    console.print(f"[bold cyan]Task:[/bold cyan] {task}\n")
    console.print("[yellow]Starting agent...[/yellow]")
    
    try:
        agent = DefaultAgent(
            LitellmModel(model_name=model_name),
            LocalEnvironment(),
            **yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text())["agent"],
        )
        
        # Add progress callback
        original_step = agent.step
        step_count = [0]  # Use list to allow modification in nested function
        
        def step_with_progress():
            step_count[0] += 1
            console.print(f"[dim]Step {step_count[0]}: Querying LLM...[/dim]")
            result = original_step()
            console.print(f"[dim]Step {step_count[0]}: Executed action, got observation[/dim]")
            return result
        
        agent.step = step_with_progress
        
        console.print("[bold green]Agent running...[/bold green] (this may take a while)\n")
        exit_status, result = agent.run(task)
        
        console.print(f"\n[bold green]✅ Agent completed![/bold green]")
        console.print(f"[bold]Exit status:[/bold] {exit_status}")
        console.print(f"[bold]Result:[/bold] {result[:200]}..." if len(result) > 200 else f"[bold]Result:[/bold] {result}")
        console.print(f"[bold]Total steps:[/bold] {step_count[0]}")
        console.print(f"[bold]Model calls:[/bold] {agent.model.n_calls}")
        console.print(f"[bold]Total cost:[/bold] ${agent.model.cost:.4f}")
        
        # Save trajectory
        output_path = output or Path("hello_world_traj.json")
        save_traj(agent, output_path, exit_status=exit_status, result=result)
        console.print(f"\n[bold green]Trajectory saved to:[/bold green] {output_path}")
        
        return agent
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user[/bold red]")
        if 'agent' in locals():
            output_path = output or Path("hello_world_traj.json")
            save_traj(agent, output_path, exit_status="Interrupted", result="User interrupted")
            console.print(f"[dim]Partial trajectory saved to:[/dim] {output_path}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        logger.error(f"Error running agent: {e}", exc_info=True)
        if 'agent' in locals():
            output_path = output or Path("hello_world_traj.json")
            save_traj(agent, output_path, exit_status="Error", result=str(e), extra_info={"error": str(e)})
            console.print(f"[dim]Error trajectory saved to:[/dim] {output_path}")
        raise


if __name__ == "__main__":
    app()
