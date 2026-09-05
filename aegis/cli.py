import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from aegis.defense.sanitizers.text import InputSanitizer
from aegis.defense.judge import ResilientLLMJudge
from aegis.defense.mcp_gate import MCPRuntimeGuard
from aegis.auditor.runner import CodeAuditor

console = Console()

@click.group()
def main():
    """Aegis-LLM: Enterprise AI Security Auditing & Defense Framework[cite: 17]."""
    pass

@main.command()
@click.argument("target", type=click.Path(exists=True))
def audit(target):
    """Scan source code for prompt leaks, embedded secrets, and OWASP LLM vulnerabilities[cite: 17]."""
    console.print(Panel.fit("[bold cyan]Aegis-LLM Security Auditor[/bold cyan]", border_style="cyan"))
    auditor = CodeAuditor(target)
    results = auditor.run()

    if not results:
        console.print("[green]✓ No critical AI anti-patterns detected in source.[/green]")
        return

    table = Table(title="Vulnerability Audit Findings", show_header=True, header_style="bold magenta")
    table.add_column("Location", style="dim")
    table.add_column("Rule", style="yellow")
    table.add_column("Severity", style="red bold")
    table.add_column("Finding", style="white")
    table.add_column("Remediation", style="green")

    for issue in results:
        table.add_row(
            f"{issue['file']}:{issue['line']}",
            issue["rule"],
            issue["severity"],
            issue["finding"],
            issue["remediation"]
        )

    console.print(table)

@main.command(name="test-defense")
@click.option("--text", "-t", required=True, help="Input prompt text to test against defense filters.")
def test_defense(text):
    """Test a prompt string through Unicode canonicalization and LLM Judge evaluation[cite: 17]."""
    console.print(Panel.fit("[bold yellow]Aegis Defense Pipeline[/bold yellow]", border_style="yellow"))
    
    cleaned = InputSanitizer.canonicalize(text)
    heuristics = InputSanitizer.scan_heuristics(cleaned)

    console.print(f"[bold]Original Length:[/bold] {len(text)} | [bold]Cleaned Length:[/bold] {len(cleaned)}")
    if heuristics:
        console.print(f"[red]⚠️ Heuristics Triggered:[/red] {heuristics}")

    judge = ResilientLLMJudge()
    decision = judge.evaluate(cleaned)

    if decision["allowed"]:
        console.print(f"[green]✓ ALLOWED[/green] (Risk Score: {decision['risk_score']}) - {decision['reason']}")
    else:
        console.print(f"[bold red]⛔ BLOCKED[/bold red] (Risk Score: {decision['risk_score']}) - {decision['reason']}")

@main.command(name="mcp-inspect")
@click.argument("description")
def mcp_inspect(description):
    """Audit an MCP tool description for hidden comments, ASCII smuggling, or imperative hijacking[cite: 17]."""
    console.print(Panel.fit("[bold blue]MCP Tool Description Inspector[/bold blue]", border_style="blue"))
    guard = MCPRuntimeGuard()
    res = guard.audit_tool_description(description)

    if res["has_issues"]:
        console.print("[red]❌ Tool Description Failed Security Audit:[/red]")
        for f in res["findings"]:
            console.print(f"  • {f}")
    else:
        console.print("[green]✓ Tool description is clean and complies with contract standards.[/green]")

if __name__ == "__main__":
    main()
