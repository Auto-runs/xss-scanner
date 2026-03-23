"""
utils/logger.py
Centralized, colorized logging with Rich.
"""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich import box
import time

_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error":   "bold red",
    "finding": "bold magenta",
    "debug":   "dim white",
    "muted":   "dim cyan",
})

console = Console(theme=_theme, highlight=False)
_verbose = False


def set_verbose(v: bool):
    global _verbose
    _verbose = v


def banner():
    art = """
 ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    console.print(art, style="bold green")
    console.print(
        "  [dim]Next-Generation XSS Detection Framework v2.0[/dim]  "
        "[bold red]⚠ Authorized Use Only[/bold red]\n"
    )


def info(msg: str):
    console.print(f"  [info]ℹ[/info]  {msg}")


def success(msg: str):
    console.print(f"  [success]✓[/success]  {msg}")


def warn(msg: str):
    console.print(f"  [warning]⚠[/warning]  {msg}")


def error(msg: str):
    console.print(f"  [error]✗[/error]  {msg}")


def finding(url: str, param: str, payload: str, xss_type: str, context: str):
    panel = Panel(
        f"[bold white]URL:[/bold white]     {url}\n"
        f"[bold white]Param:[/bold white]   [yellow]{param}[/yellow]\n"
        f"[bold white]Type:[/bold white]    [red]{xss_type.upper()}[/red]\n"
        f"[bold white]Context:[/bold white] [cyan]{context}[/cyan]\n"
        f"[bold white]Payload:[/bold white] [green]{payload[:120]}[/green]",
        title="[bold red]⚡ XSS FOUND[/bold red]",
        border_style="red",
        box=box.DOUBLE,
    )
    console.print(panel)


def debug(msg: str):
    if _verbose:
        console.print(f"  [debug]·[/debug]  {msg}")


def progress(msg: str):
    console.print(f"  [muted]→[/muted]  {msg}")


def section(title: str):
    console.rule(f"[bold cyan]{title}[/bold cyan]")
