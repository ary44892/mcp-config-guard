# Config Guard

**Zero-dependency security linter for MCP configurations.**

Scans your `.mcp.json` for 54 types of security vulnerabilities before any MCP server starts. No API keys. No cloud. No LLM required.

[![PyPI version](https://badge.fury.io/py/mcp-config-guard.svg)](https://pypi.org/project/mcp-config-guard/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://pypi.org/project/mcp-config-guard/)

## Why?

**43% of public MCP servers have command injection flaws** (BlueRock TechReport 2026). Every MCP config you use is a trust boundary — and most developers never audit them.

Config Guard catches what humans miss:

- Typosquatted packages that look like real ones
- Servers with known CVEs (22 CVEs across 20 packages)
- 44 confirmed malicious packages (JFrog, Kaspersky, Lazarus APT, SANDWORM_MODE)
- Secret leakage in environment variables
- Rug-pull vectors (`npx @latest` auto-updates)
- Shadow servers exposing via tunnels

## Install

```bash
pip install mcp-config-guard
```

> **Note:** The package was renamed to `mcp-config-guard` on PyPI. Both `config-guard` and `mcp-config-guard` CLI commands work after installation.

## Quick Start

```bash
# Scan your current directory's .mcp.json
mcp-config-guard

# Scan a specific project
mcp-config-guard --path /my/project

# Auto-discover all MCP configs on your system
mcp-config-guard --discover

# CI/CD integration (SARIF output for GitHub Code Scanning)
mcp-config-guard --sarif > results.sarif

# JSON output for scripting
mcp-config-guard --json
```

## 54 Security Checks

Every check is mapped to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-security/). See [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md) for full CWE mappings.

| # | Check | Risk | OWASP |
|---|-------|------|-------|
| 1 | Network exposure (non-localhost URLs) | HIGH | MCP-03 |
| 2 | Rug pulls (`npx @latest` auto-update) | HIGH | MCP-07 |
| 3 | Secret leakage (API keys in args/env) | HIGH | MCP-04 |
| 4 | Command injection (`shell=True`) | CRITICAL | MCP-01 |
| 5 | Path traversal (`..` in arguments) | MEDIUM | MCP-05 |
| 6 | Typosquat detection (Levenshtein distance) | HIGH | MCP-07 |
| 7 | Dangerous permissions (`--no-sandbox`, `sudo`) | HIGH | MCP-06 |
| 8 | Missing authentication on HTTP transport | MEDIUM | MCP-08 |
| 9 | Sensitive path access (`.ssh`, `.aws`, `.env`) | HIGH | MCP-04 |
| 10 | Overbroad filesystem access (`/`, `C:\`) | MEDIUM | MCP-06 |
| 11 | Environment variable leaks (hardcoded secrets) | MEDIUM | MCP-04 |
| 12 | Excessive server count (attack surface) | LOW | MCP-10 |
| 13 | Known CVEs (22 CVEs across 20 packages) | CRITICAL | MCP-09 |
| 14 | Symlink bypass (CVE-2025-53109) | HIGH | MCP-05 |
| 15 | Shadow servers (ngrok, cloudflared, `0.0.0.0`) | HIGH | MCP-05 |
| 16 | Code execution (`eval`/`exec` patterns) | CRITICAL | MCP-01 |
| 17 | Known malicious packages (44 confirmed malware) | CRITICAL | MCP-07 |
| 18 | Deprecated SSE transport (no per-request auth) | MEDIUM | MCP-03 |
| 19 | Shell servers (raw shell as MCP server) | CRITICAL | MCP-01 |
| 20 | Unpinned packages (npx/uvx without version) | MEDIUM | MCP-04 |

## CVE Database

Config Guard tracks known vulnerable MCP packages:

| Package | CVE | Severity |
|---------|-----|----------|
| `mcp-remote` | CVE-2025-6514 | Critical (CVSS 9.6) |
| `@modelcontextprotocol/server-git` | CVE-2025-68145 | Critical |
| `mcp-server-git` | CVE-2026-27735 | Medium |
| `@anthropic/mcp-server-filesystem` | CVE-2025-53109 | High |
| `gemini-mcp-tool` | CVE-2026-0755 | Critical |
| `mcp-vegalite-server` | CVE-2026-1977 | Critical |
| `github-kanban-mcp` | CVE-2026-0756 | High |
| `godot-mcp` | CVE-2026-25546 | High |
| `fermat-mcp` | CVE-2026-2008 | Critical |
| `@anthropic/mcp-inspector` | CVE-2026-23744 | Critical (CVSS 9.8) |

Config Guard also detects **confirmed malicious packages** (e.g., `postmark-mcp`, `@lanyer640/mcp-runcommand-server`) that contain reverse shells or malware payloads.

## Output Formats

### Human-readable (default)
```
MCP Security Scan Results
