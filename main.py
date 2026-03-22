"""
main.py
-------
Entry point for the Agentic Log Analyzer.

Usage
-----
  # Start the continuous polling daemon
  python main.py run

  # Analyse a single log file / JSON event on demand
  python main.py analyse --file sample_log.json

  # List the most recent analysed cases
  python main.py list [--limit 20]

  # View a specific case
  python main.py show <case_id>

  # Submit feedback for a case
  python main.py feedback <case_id> --result correct|incorrect|partial [--notes "..."]
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

import schedule
import time
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from log_analyzer_agent import LogAnalyzerAgent

console = Console()

# --------------------------------------------------------------------------
# Logging setup
# --------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quieten noisy third-party loggers
    for lib in ("urllib3", "openai", "httpx", "httpcore"):
        logging.getLogger(lib).setLevel(logging.WARNING)


# --------------------------------------------------------------------------
# Config loader
# --------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    cfg_path = Path(path)
    if not cfg_path.exists():
        console.print(f"[red]Config file not found: {cfg_path.resolve()}[/red]")
        sys.exit(1)
    with cfg_path.open() as fh:
        cfg = yaml.safe_load(fh)
    console.print(f"[dim]Loaded config from {cfg_path.resolve()}[/dim]")
    return cfg


# --------------------------------------------------------------------------
# Rich display helpers
# --------------------------------------------------------------------------

def display_analysis(result: Dict[str, Any]) -> None:
    case_id = result["case_id"]
    analysis = result["analysis"]
    event = result["event"]
    similar = result["similar_cases"]
    alert_fired = result["alert_fired"]
    alert_results = result["alert_results"]

    severity_colour = {
        "CRITICAL": "bold red",
        "ERROR": "red",
        "WARNING": "yellow",
        "INFO": "green",
        "UNKNOWN": "dim",
    }.get(analysis.get("severity", "UNKNOWN"), "white")

    header = (
        f"[{severity_colour}]{analysis.get('severity','?')}[/{severity_colour}]  "
        f"Case #{case_id}  |  "
        f"[cyan]{event.get('source','?')}[/cyan] @ {event.get('_time','?')}"
    )
    console.rule(header)

    console.print(Panel(analysis.get("summary", ""), title="[bold]Summary[/bold]", expand=False))

    console.print("\n[bold underline]Root Cause[/bold underline]")
    console.print(analysis.get("root_cause", "N/A"))

    console.print("\n[bold underline]Recommended Solution[/bold underline]")
    console.print(analysis.get("solution", "N/A"))

    comps = ", ".join(analysis.get("related_components", [])) or "N/A"
    console.print(
        f"\n[dim]Related components:[/dim] {comps}   "
        f"[dim]Confidence:[/dim] {analysis.get('confidence', 0):.0%}"
    )

    if similar:
        console.print(f"\n[dim]↳ Used {len(similar)} similar past case(s) as context.[/dim]")

    if alert_fired:
        channels = ", ".join(
            f"{ch}:[green]{st}[/green]" if st == "sent" else f"{ch}:[red]{st}[/red]"
            for ch, st in alert_results.items()
        )
        console.print(f"\n[bold yellow]⚠ ALERT FIRED[/bold yellow]  → {channels}")

    console.print()


def display_cases_table(cases: list) -> None:
    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Time", width=22)
    table.add_column("Level", width=10)
    table.add_column("Source", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Summary", no_wrap=False)
    table.add_column("Feedback", width=12)
    table.add_column("Conf", width=6)

    sev_colour = {"CRITICAL": "red", "ERROR": "red", "WARNING": "yellow", "INFO": "green"}

    for c in cases:
        sev = c.get("severity") or "?"
        colour = sev_colour.get(sev.upper(), "white")
        table.add_row(
            str(c["id"]),
            c.get("created_at", "")[:19],
            c.get("log_level", ""),
            c.get("log_source", ""),
            f"[{colour}]{sev}[/{colour}]",
            (c.get("summary") or "")[:70],
            c.get("user_feedback") or "[dim]–[/dim]",
            f"{(c.get('confidence') or 0):.0%}",
        )
    console.print(table)


# --------------------------------------------------------------------------
# Sub-command handlers
# --------------------------------------------------------------------------

def cmd_run(agent: LogAnalyzerAgent, cfg: Dict[str, Any]) -> None:
    """Continuous polling daemon."""
    interval = cfg["splunk"].get("poll_interval_seconds", 60)
    console.print(
        f"[bold green]Daemon started[/bold green] – polling every {interval}s. "
        "Press Ctrl-C to stop.\n"
    )

    def tick():
        results = agent.run_cycle()
        for r in results:
            display_analysis(r)

    # Run immediately on startup, then schedule
    tick()
    schedule.every(interval).seconds.do(tick)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Daemon stopped.[/yellow]")


def cmd_analyse(agent: LogAnalyzerAgent, args: argparse.Namespace) -> None:
    """Analyse a single JSON log event from a file."""
    file_path = Path(args.file)
    if not file_path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        sys.exit(1)
    with file_path.open() as fh:
        raw = json.load(fh)
    # Accept either a single dict or a list of events
    events = raw if isinstance(raw, list) else [raw]
    for event in events:
        result = agent.process_single(event)
        display_analysis(result)


def cmd_list(agent: LogAnalyzerAgent, args: argparse.Namespace) -> None:
    cases = agent.list_recent_cases(limit=args.limit)
    if not cases:
        console.print("[dim]No cases found.[/dim]")
        return
    display_cases_table(cases)


def cmd_show(agent: LogAnalyzerAgent, args: argparse.Namespace) -> None:
    case = agent.get_case(args.case_id)
    if not case:
        console.print(f"[red]Case #{args.case_id} not found.[/red]")
        sys.exit(1)

    console.print_json(json.dumps(case, indent=2, default=str))


def cmd_feedback(agent: LogAnalyzerAgent, args: argparse.Namespace) -> None:
    valid = {"correct", "incorrect", "partial"}
    result = args.result.lower()
    if result not in valid:
        console.print(f"[red]Invalid feedback value. Choose from: {valid}[/red]")
        sys.exit(1)
    agent.submit_feedback(args.case_id, result, notes=args.notes or "")
    console.print(
        f"[green]✔ Feedback '{result}' recorded for case #{args.case_id}.[/green]"
    )


# --------------------------------------------------------------------------
# CLI parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Agentic AI Log Analyzer powered by MiniMax + Splunk",
    )
    p.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    sub = p.add_subparsers(dest="command", required=True)

    # run
    sub.add_parser("run", help="Start continuous polling daemon")

    # analyse
    analyse_p = sub.add_parser("analyse", help="Analyse a JSON log file")
    analyse_p.add_argument("--file", required=True, help="Path to JSON log event file")

    # list
    list_p = sub.add_parser("list", help="List recent analysed cases")
    list_p.add_argument("--limit", type=int, default=20, help="Number of cases to show")

    # show
    show_p = sub.add_parser("show", help="Show full details of a case")
    show_p.add_argument("case_id", type=int)

    # feedback
    fb_p = sub.add_parser("feedback", help="Submit feedback for a case")
    fb_p.add_argument("case_id", type=int)
    fb_p.add_argument("--result", required=True,
                      help="Feedback: correct | incorrect | partial")
    fb_p.add_argument("--notes", default="", help="Optional free-text notes")

    return p


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    cfg = load_config(args.config)

    agent = LogAnalyzerAgent(cfg)

    try:
        if args.command == "run":
            cmd_run(agent, cfg)
        elif args.command == "analyse":
            cmd_analyse(agent, args)
        elif args.command == "list":
            cmd_list(agent, args)
        elif args.command == "show":
            cmd_show(agent, args)
        elif args.command == "feedback":
            cmd_feedback(agent, args)
    finally:
        agent.close()


if __name__ == "__main__":
    main()
