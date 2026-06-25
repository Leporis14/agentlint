# agentlint

> A security scanner for MCP server configs — catch dangerous permissions, hardcoded secrets, and missing guardrails before you ship.

[![PyPI version](https://img.shields.io/pypi/v/leporis-agentlint)](https://pypi.org/project/leporis-agentlint/)
[![License](https://img.shields.io/pypi/l/leporis-agentlint?v=2)](https://pypi.org/project/leporis-agentlint/)
[![Stars](https://img.shields.io/github/stars/Leporis14/agentlint)](https://github.com/Leporis14/agentlint)

## Install

```bash
pip install leporis-agentlint
```

## Usage

### Local scan

```bash
$ agentlint scan mcp.json
```

```
┌──────────────────────────────────────────────────────┐
│  github-server  ######....  6/10                     │
│  !!  Hardcoded secret: env var 'GITHUB_TOKEN'        │
│      contains a literal secret value.                │
│  !   No approval gate: server is missing             │
│      'requireApproval' or 'humanInLoop' field.       │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  filesystem  #####.....  5/10                        │
│  !!  Broad filesystem access: arg '/home' exposes    │
│      sensitive paths.                                │
│  !   No approval gate: server is missing             │
│      'requireApproval' or 'humanInLoop' field.       │
└──────────────────────────────────────────────────────┘

┌─────────────────── Summary ──────────────────────────┐
│  Servers scanned     2                               │
│  Average risk score  5.5 / 10                        │
│  Critical findings   2                               │
│  Warnings            2                               │
│  Total findings      4                               │
└──────────────────────────────────────────────────────┘

       Highest-Risk Servers
 Server          Score
 github-server   ######.... 6/10
 filesystem      #####..... 5/10
```

### Machine-readable output

```bash
$ agentlint scan mcp.json --json
```

```json
{
  "github-server": {
    "score": 6,
    "findings": [
      {"level": "critical", "detail": "Hardcoded secret: env var 'GITHUB_TOKEN' contains a literal secret value."},
      {"level": "warning", "detail": "No approval gate: server is missing 'requireApproval' or 'humanInLoop' field."}
    ]
  }
}
```

## Checks

| # | Check | What it catches | Severity |
|---|-------|----------------|----------|
| 1 | **Hardcoded secrets** | API keys, tokens, passwords, JWTs baked into `env` values | Critical |
| 2 | **Broad filesystem access** | Args exposing `/home`, `/etc`, `/var`, `~/`, root, Windows drives | Critical |
| 3 | **Missing env vars** | Server name suggests auth (github, postgres, stripe…) but `env` is empty | Warning |
| 4 | **No approval gate** | Missing `requireApproval` or `humanInLoop` field | Warning |

Each server gets a risk score **1–10**. Green (≤3), yellow (4–6), red (7+).

## CI / GitHub Actions

```bash
$ agentlint ci
```

```
agentlint: 4 servers scanned, 3 critical violations, 2 servers scored >= 7. Build failed.
```

Exits `0` if clean, `1` if any server scores ≥ 7. Auto-discovers config from `claude_desktop_config.json`, `.mcp.json`, or `mcp.json` in the repo root.

```yaml
# .github/workflows/agentlint.yml
name: agentlint
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  agentlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install agentlint
        run: pip install leporis-agentlint
      - name: Run agentlint CI check
        run: agentlint ci
```

## Why

AI agents are shipping with MCP servers that get filesystem access, network access, and raw API keys handed to them at launch. There is no built-in sandbox, no mandatory approval step, and no standard way to audit what a given config actually grants. The industry is racing to give agents *more* capabilities while the security surface grows unchecked. **agentlint** is a single-file scanner that reads your MCP config and tells you what's dangerous — before your agent touches production.
