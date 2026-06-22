#!/usr/bin/env python3
"""agentlint — Audit MCP server configs for security and best-practice risks."""

import json
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    name="agentlint",
    help="Lint MCP server configurations for security risks.",
    no_args_is_help=True,
)

console = Console()


@app.callback()
def _main_callback() -> None:
    """Entry point — use 'agentlint scan <file>' to audit a config."""
    pass  # actual work is in the scan subcommand

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

SECRET_KEY_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\b(?:api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?token|access[_-]?key|private[_-]?key|bearer|jwt|credential)\b",
    ]
]

SECRET_VALUE_PATTERNS = [
    re.compile(p) for p in [
        # GitHub tokens
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        # Slack tokens
        r"xox[bp][a-z]?-[\d]+-[A-Za-z0-9-]+",
        # Generic hex/base64-looking tokens (allow hyphens, moderate confidence)
        r"\b[A-Za-z0-9+/=-]{32,}\b",
        # JWT-ish
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        # AWS keys
        r"AKIA[0-9A-Z]{16}",
        # Slack webhooks
        r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+",
    ]
]

BROAD_PATH_PATTERNS = [
    re.compile(p) for p in [
        r"(?:^|\s)~/",                  # ~/ anywhere (start or after whitespace)
        r"^~$",                         # bare ~
        r"^/home/",                     # user homes
        r"^/etc/",                      # system config
        r"^/var/",                      # var data
        r"^/tmp/",                      # temp
        r"^/$",                         # filesystem root
        r"^/(?!usr/(local/)?bin/?)",    # any root-level path except /usr/bin
        r"^[A-Z]:\\",                   # Windows root drives
    ]
]

AUTH_KEYWORDS = {
    "github", "gitlab", "bitbucket", "postgres", "postgresql", "mysql",
    "mariadb", "slack", "discord", "jira", "confluence", "aws", "gcp",
    "azure", "docker", "kubernetes", "k8s", "heroku", "vercel", "netlify",
    "stripe", "twilio", "sendgrid", "mailgun", "auth0", "okta", "firebase",
    "supabase", "redis", "mongodb", "elasticsearch", "snowflake", "datadog",
    "pagerduty", "opsgenie", "sentry", "linear", "notion", "airtable",
    "salesforce", "hubspot", "zendesk", "figma",
}


def is_broad_path(arg: str) -> bool:
    """Return True if *arg* looks like overly broad filesystem access."""
    return any(p.search(arg) for p in BROAD_PATH_PATTERNS)


def secret_key_looks_hardcoded(value: str) -> bool:
    """Return True when a value looks like a literal secret instead of a
    placeholder or env-var reference."""
    if not isinstance(value, str) or not value.strip():
        return False
    # Common placeholder patterns — skip
    placeholder_markers = ["<", ">", "your-", "replace", "change", "TODO", "xxx", "****", "..."]
    if any(m in value for m in placeholder_markers):
        return False
    # Variables referencing the shell / other env vars are ok
    if value.startswith("$") or value.startswith("${"):
        return False
    return any(p.search(value) for p in SECRET_VALUE_PATTERNS)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, level: str, detail: str) -> None:
        self.level = level       # "critical", "warning", "ok"
        self.detail = detail


def _key_has_secret_name(key: str) -> bool:
    """Check whether *key* contains a secret-sounding component.
    Replaces underscores with spaces so word-boundary patterns work."""
    normalised = key.replace("_", " ")
    return any(p.search(normalised) for p in SECRET_KEY_PATTERNS)


def audit_server(name: str, config: dict) -> tuple[list[Finding], int]:
    """Audit a single MCP server entry.  Returns (findings, risk_score)."""
    findings: list[Finding] = []
    score = 0

    # 1. Hardcoded secrets ---------------------------------------------------
    env = config.get("env") or {}

    for key, value in env.items():
        str_val = str(value)
        key_is_secret = _key_has_secret_name(key)
        value_is_hardcoded = secret_key_looks_hardcoded(str_val)
        has_real_value = bool(str_val.strip()) and not str_val.startswith("$")

        if key_is_secret and value_is_hardcoded:
            findings.append(Finding(
                "critical",
                f"Hardcoded secret: env var '{key}' contains a literal secret value.",
            ))
            score += 4
        elif key_is_secret and has_real_value:
            findings.append(Finding(
                "warning",
                f"Possible secret: env var '{key}' has a non-empty value that may be a credential.",
            ))
            score += 2
        elif value_is_hardcoded:
            findings.append(Finding(
                "warning",
                f"Possible secret: env var '{key}' value looks like a credential.",
            ))
            score += 2

    # 2. Overly broad filesystem access --------------------------------------
    args = config.get("args") or []
    for arg in args:
        arg_s = str(arg)
        if is_broad_path(arg_s):
            findings.append(Finding(
                "critical",
                f"Broad filesystem access: arg '{arg_s}' exposes sensitive paths.",
            ))
            score += 3

    # 3. Missing env vars for auth-requiring services ------------------------
    name_lower = name.lower()
    needs_auth = any(kw in name_lower for kw in AUTH_KEYWORDS)

    if needs_auth and not env:
        findings.append(Finding(
            "warning",
            f"Missing env vars: server '{name}' likely needs auth but has no env block.",
        ))
        score += 2

    # 4. Missing approval gate -----------------------------------------------
    has_approval = (
        "requireApproval" in config
        or "require_approval" in config
        or "humanInLoop" in config
        or "human_in_loop" in config
    )
    if not has_approval:
        findings.append(Finding(
            "warning",
            "No approval gate: server is missing 'requireApproval' or 'humanInLoop' field.",
        ))
        score += 2

    # Clamp score to 1-10
    score = max(1, min(score, 10))
    return findings, score


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

LEVEL_COLORS = {"critical": "red", "warning": "yellow", "ok": "green"}
LEVEL_ICONS = {"critical": "!!", "warning": "! ", "ok": "ok"}


def score_color(score: int) -> str:
    if score <= 3:
        return "green"
    elif score <= 6:
        return "yellow"
    return "red"


def score_bar(score: int) -> Text:
    """Render a 10-segment bar: # for each point."""
    bar_chars = []
    for i in range(1, 11):
        if i <= score:
            bar_chars.append("#")
        else:
            bar_chars.append(".")
    color = score_color(score)
    return Text("".join(bar_chars), style=color)


@app.command(name="scan")
def scan_cmd(
    config_file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to a JSON config file containing an 'mcpServers' block.",
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON instead of rich formatting."),
    ] = False,
) -> None:
    """Scan an MCP server configuration file for security risks."""

    # Parse ------------------------------------------------------------------
    try:
        raw = json.loads(config_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] invalid JSON in {config_file} — {exc}")
        raise typer.Exit(code=1)

    servers = raw.get("mcpServers") or raw
    if not isinstance(servers, dict):
        console.print(
            f"[red]Error:[/red] expected object at 'mcpServers' key or top level; "
            f"got {type(servers).__name__}."
        )
        raise typer.Exit(code=1)

    # Audit every server -----------------------------------------------------
    results: dict[str, dict] = {}
    for srv_name, srv_config in servers.items():
        if not isinstance(srv_config, dict):
            results[srv_name] = {
                "findings": [Finding("warning", f"Skipped: config is {type(srv_config).__name__}, not an object.")],
                "score": 1,
            }
            continue
        findings, score = audit_server(srv_name, srv_config)
        results[srv_name] = {"findings": findings, "score": score}

    # JSON output ------------------------------------------------------------
    if json_output:
        json_results = {}
        for name, data in results.items():
            json_results[name] = {
                "score": data["score"],
                "findings": [
                    {"level": f.level, "detail": f.detail} for f in data["findings"]
                ],
            }
        console.print_json(data=json_results)
        return

    # Rich output ------------------------------------------------------------
    # Per-server tables
    for srv_name, data in results.items():
        findings: list[Finding] = data["findings"]
        score: int = data["score"]

        bar = score_bar(score)
        color = score_color(score)

        title = Text.assemble(
            (srv_name, f"bold {color}"), "  ", bar, f"  {score}/10"
        )
        table = Table(title=title, show_header=False, expand=True, box=None)
        table.add_column("Icon", width=2)
        table.add_column("Finding")

        if not findings:
            table.add_row("[green]ok[/green]", Text("No issues found", style="green"))
        else:
            for f in findings:
                icon = LEVEL_ICONS[f.level]
                style = LEVEL_COLORS[f.level]
                table.add_row(f"[{style}]{icon}[/{style}]", Text(f.detail, style=style))

        console.print(Panel(table, border_style=color))
        console.print()

    # Summary ----------------------------------------------------------------
    all_scores = [d["score"] for d in results.values()]
    total_findings = sum(len(d["findings"]) for d in results.values())
    criticals = sum(
        1 for d in results.values() for f in d["findings"] if f.level == "critical"
    )
    warnings_ = sum(
        1 for d in results.values() for f in d["findings"] if f.level == "warning"
    )

    avg_score = round(sum(all_scores) / max(len(all_scores), 1), 1)

    summary = Table(title="Risk Summary", show_header=True, box=None)
    summary.add_column("Metric")
    summary.add_column("Value")
    summary.add_row("Servers scanned", str(len(results)))
    summary.add_row("Average risk score", f"{avg_score} / 10")
    summary.add_row("Critical findings", str(criticals), style="red")
    summary.add_row("Warnings", str(warnings_), style="yellow")
    summary.add_row("Total findings", str(total_findings))

    overall_color = score_color(int(avg_score))
    console.print(Panel(summary, border_style=overall_color, title="[bold]Summary[/bold]"))

    # Top risk servers
    if len(results) > 1:
        console.print()
        worst = sorted(results.items(), key=lambda kv: kv[1]["score"], reverse=True)[:3]
        risk_table = Table(title="Highest-Risk Servers", show_header=True, box=None)
        risk_table.add_column("Server")
        risk_table.add_column("Score")
        for name, data in worst:
            s = data["score"]
            risk_table.add_row(name, score_bar(s) + Text(f" {s}/10"))
        console.print(risk_table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
