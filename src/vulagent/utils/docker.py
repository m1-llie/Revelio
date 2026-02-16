def copy_from_container(docker_env, source, path, console):
    copied = None
    try:
        copied = docker_env.copy_from(source, path)
        console.print(f"[bold green]{source} copied to:[/bold green] {copied}")
    except FileNotFoundError:
        console.print("[bold yellow]No {source} inside the container.[/bold yellow]")
    except RuntimeError as error:
        console.print(f"[bold red]Failed to copy {source}:[/bold red] {error}")
    return copied

