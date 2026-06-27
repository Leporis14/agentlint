#!/usr/bin/env python3
"""agentlint — Audit MCP server configs for security and best-practice risks."""

import json
import re
from pathlib import Path
from typing import Annotated, Optional

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
        # Generic hex/base64-looking tokens (no / — avoids matching filesystem paths)
        r"\b[A-Za-z0-9_=-]{32,}\b",
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

EXFIL_KEYWORDS = {
    "upload", "email", "webhook", "smtp", "send_mail", "http_post",
    "browser_submit", "s3_put", "ftp", "curl", "wget",
}

SHELL_NET_KEYWORDS = {
    "bash", "sh", "curl", "wget", "python", "node", "exec", "eval", "nc", "ncat",
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

    # 1b. Secrets in CLI args --------------------------------------------------
    args = config.get("args") or []
    for arg in args:
        arg_s = str(arg)
        if secret_key_looks_hardcoded(arg_s):
            findings.append(Finding(
                "critical",
                f"Secret in CLI args: value '{arg_s}' leaks into shell history and process lists.",
            ))
            score += 4

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

    # 5. Exfiltration-capable tools --------------------------------------------
    # Collect all scannable text: server name, command, and args
    search_texts: list[str] = [name]
    for field in ("command", "args"):
        val = config.get(field)
        if isinstance(val, list):
            search_texts.extend(str(v) for v in val)
        elif isinstance(val, str):
            search_texts.append(val)

    search_blob = " ".join(search_texts).lower()
    matched = [kw for kw in EXFIL_KEYWORDS if kw in search_blob]

    for kw in matched:
        if has_approval:
            findings.append(Finding(
                "warning",
                f"Exfiltration-capable tool '{kw}' is present, but protected by an approval gate.",
            ))
            score += 1
        else:
            findings.append(Finding(
                "critical",
                f"Exfiltration-capable tool detected: '{kw}' can silently send data outside the environment — requires an explicit approval gate.",
            ))
            score += 4

    # 6. Compound: secret + shell/network = dangerous combo -------------------
    has_secret_finding = any(
        "Hardcoded secret" in f.detail or "Secret in CLI args" in f.detail
        for f in findings
    )
    if has_secret_finding:
        # Normalise runtime keywords — "node" / "python" as the command
        # interpreter are not inherently shell access, but they ARE
        # dangerous when they appear in args (e.g. `python -c '...'`).
        RUNTIME_ONLY = frozenset({"node", "python"})

        cmd = config.get("command", "")
        cmd_lower = (cmd or "").lower()
        args = config.get("args") or []
        if isinstance(args, list):
            args_lower = " ".join(str(v).lower() for v in args)
        else:
            args_lower = ""

        name_lower = name.lower()
        search_blob = " ".join([name_lower, cmd_lower, args_lower])

        shell_match: str | None = None
        for kw in SHELL_NET_KEYWORDS:
            if kw not in search_blob:
                continue
            if kw in RUNTIME_ONLY and kw == cmd_lower:
                # `node` or `python` as the exact command interpreter — skip
                continue
            shell_match = kw
            break

        if shell_match is not None:
            findings.append(Finding(
                "critical",
                "Dangerous combo: server has secret credentials AND shell/network access — high exfiltration risk.",
            ))
            score += 5

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


def _load_and_audit(config_file: Path) -> dict[str, dict]:
    """Parse *config_file* and audit every server.  Returns {name: {findings, score}}."""
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

    return results


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

    results = _load_and_audit(config_file)

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
# CI command (plain-text, exit-code driven)
# ---------------------------------------------------------------------------

_CI_CONFIG_CANDIDATES = [
    Path("claude_desktop_config.json"),
    Path(".mcp.json"),
    Path("mcp.json"),
]


def _discover_config() -> Path:
    """Find the first existing MCP config file in the current directory."""
    for candidate in _CI_CONFIG_CANDIDATES:
        if candidate.exists():
            return candidate
    names = ", ".join(str(p) for p in _CI_CONFIG_CANDIDATES)
    print(f"agentlint: error: no config file found (looked for: {names})", file=__import__("sys").stderr)
    raise typer.Exit(code=2)


@app.command(name="ci")
def ci_cmd(
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config", "-c",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to config file. Auto-detected if omitted.",
        ),
    ] = None,
) -> None:
    """Run agentlint in CI mode.  Exits non-zero when any server scores 7 or above."""

    config_path = config if config is not None else _discover_config()
    results = _load_and_audit(config_path)

    total = len(results)
    if total == 0:
        print("agentlint: no servers found. Build passed.")
        raise typer.Exit(code=0)

    criticals = sum(
        1 for d in results.values() for f in d["findings"] if f.level == "critical"
    )
    max_score = max(d["score"] for d in results.values())
    failed = max_score >= 7

    # One-line summary
    msg = f"agentlint: {total} server{'s' if total != 1 else ''} scanned, "
    msg += f"{criticals} critical violation{'s' if criticals != 1 else ''}"
    if failed:
        over = sum(1 for d in results.values() if d["score"] >= 7)
        msg += f", {over} server{'s' if over != 1 else ''} scored >= 7"
    msg += ". Build failed." if failed else ". Build passed."

    print(msg)
    raise typer.Exit(code=1 if failed else 0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
