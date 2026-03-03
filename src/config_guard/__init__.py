#!/usr/bin/env python3
"""
Config Guard v2.0.0 — Zero-dependency security linter for MCP configurations

Fully offline, deterministic security linter for MCP configuration files.
Catches network exposure, secret leakage, auto-update risks, privilege escalation,
supply chain attacks, and 50+ dangerous patterns in .mcp.json before any server starts.
No API keys. No cloud. No LLM required.

54 security checks mapped to OWASP Agentic Security Top 10 (ASI01-ASI10):

Per-server checks:
 1. Network exposure — non-localhost URLs, 0.0.0.0 binding [ASI04]
 2. Rug pulls — npx @latest auto-update vectors [ASI07]
 3. Secret leakage — hardcoded API keys in args/env [ASI06]
 4. Command injection — shell=True in arguments [ASI02]
 5. Path traversal — '..' sequences in arguments [ASI02]
 6. Typosquat detection — Levenshtein distance on package names [ASI07]
 7. Dangerous permissions — --allow-all, --no-sandbox, sudo, Docker [ASI01]
 8. Missing auth — HTTP transport without auth headers [ASI06]
 9. Sensitive paths — access to .ssh, .aws, .env directories [ASI06]
10. Overbroad access — root/system-level filesystem grants [ASI01]
11. Env var leaks — hardcoded secrets in env config [ASI06]
13. Known CVEs — 12+ packages tracked [ASI07]
14. Symlink bypass — CVE-2025-53109 privilege escalation [ASI02]
15. Shadow servers — tunnel/public binding detection (ngrok, cloudflared) [ASI04]
16. Code execution — eval/exec/execAsync patterns (CVE-2026-0755/1977/25546) [ASI02]
17. Known malicious — confirmed malware packages [ASI07]
18. Deprecated SSE — legacy transport without per-request auth [ASI04]
19. Shell servers — raw shell interpreter as MCP server [ASI02]
20. Unpinned packages — npx/uvx without version pin [ASI07]
21. Version pinning — unpinned packages = supply chain risk [ASI07]
22. Transport security — stdio vs SSE vs HTTP risk assessment [ASI04]
23. OAuth/PKCE enforcement — remote servers without auth [ASI06]
24. Wildcard tool permissions — unrestricted tool access [ASI01]
25. Unrestricted filesystem — broad filesystem grants [ASI01]
26. Missing input validation — validation disabled via flags [ASI02]
27. Missing output sanitization — raw output enabled [ASI05]
28. Missing rate limiting — remote servers without throttling [ASI04]
29. Missing audit logging — logging explicitly disabled [ASI10]
30. Unencrypted secrets — hardcoded sensitive env vars [ASI06]
31. Docker socket exposure — container escape risk [ASI04]
32. Privilege escalation — elevated capabilities [ASI01]
33. SSRF risk — internal/private IP access [ASI04]
34. Memory/context poisoning — prompt injection flags [ASI03]
35. Supply chain downloads — raw GitHub URLs [ASI07]
36. Insecure protocols — FTP/Telnet/unencrypted WS [ASI06]
37. Excessive env vars — large configuration surface [ASI01]
38. Debug mode — verbose/debug enabled in production [ASI10]
39. Debug port — Node.js --inspect RCE risk [ASI04]
40. Multiple transports — ambiguous routing [ASI03]
41. Shell expansion — injection via metacharacters [ASI02]
42. CORS wildcard — unrestricted cross-origin access [ASI05]
43. Open redirects — unvalidated callback URLs [ASI05]
44. Excessive arguments — complex configuration [ASI01]
45. Crypto exposure — wallet/mnemonic patterns [ASI04]
46. Temp directory risk — world-writable paths [ASI08]
47. Recursive watching — CPU/memory exhaustion [ASI04]
48. Scope typosquatting — lookalike npm scopes [ASI07]
49. Missing command — server with no command or URL [ASI08]
50. Database connection strings — exposed DB URIs [ASI06]
51. Base64 obfuscation — encoded values hiding data [ASI02]
52. Duplicate servers — case-insensitive name collision [ASI08]

Global checks:
12. Excessive servers — attack surface from too many servers [ASI01]
53. No stdio servers — all remote transport [ASI03]
54. Remote-heavy ratio — >70% remote servers [ASI04]

v2.0.0 features:
- 54 checks (up from 22) mapped to OWASP Agentic Security Top 10
- Policy-as-code: YAML/JSON policy files for custom severity + enable/disable checks
- Auto-fix suggestions for common issues
- GitHub Actions workflow template support
- PyPI-ready packaging

Supports: Claude Code, Claude Desktop, Cursor, VS Code, Windsurf configs.
Output: Human-readable, JSON, SARIF v2.1.0 (CI/CD).

Usage:
    config-guard                         # Scan .mcp.json
    config-guard --json                  # JSON output
    config-guard --sarif                 # SARIF v2.1.0 output
    config-guard --path /other/dir       # Scan different dir
    config-guard --discover              # Auto-find all MCP configs
    config-guard --summary               # One-line summary output
    config-guard --policy policy.yml     # Load custom policy
    config-guard --fix                   # Show auto-fix suggestions
    config-guard --init-policy           # Generate default policy file
"""

import hashlib
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path.cwd()
__version__ = "2.0.0"

# ═══ Risk Definitions ═══

RISK_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ═══ OWASP MCP Top 10 Mapping ═══
# Maps each finding category to the relevant OWASP Agentic/MCP risk
OWASP_MAPPING = {
    "network-exposure": {"id": "MCP-03", "name": "Insecure MCP Transport", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "rug-pull": {"id": "MCP-07", "name": "Rug Pull / Supply Chain", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "secret-leak": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "command-injection": {"id": "MCP-01", "name": "Command Injection via Tool", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "path-traversal": {"id": "MCP-05", "name": "Path Traversal / File Access", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "tool-poisoning": {"id": "MCP-02", "name": "Tool Poisoning", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "config": {"id": "MCP-10", "name": "Misconfiguration", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "typosquat": {"id": "MCP-07", "name": "Supply Chain / Typosquat", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "dangerous-permission": {"id": "MCP-06", "name": "Excessive Permissions", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "missing-auth": {"id": "MCP-08", "name": "Missing Authentication", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "sensitive-path": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "overbroad-access": {"id": "MCP-06", "name": "Excessive Permissions", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "excessive-servers": {"id": "MCP-10", "name": "Misconfiguration", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "env-var-leak": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "known-vulnerable": {"id": "MCP-09", "name": "Known Vulnerable Component", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "symlink-risk": {"id": "MCP-05", "name": "Symlink Bypass / Path Traversal", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "shadow-server": {"id": "MCP-05", "name": "Shadow MCP Server / Unauthorized Exposure", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "code-execution": {"id": "MCP-01", "name": "Code Execution via eval/exec", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "known-malicious": {"id": "MCP-07", "name": "Confirmed Malicious Package", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "deprecated-transport": {"id": "MCP-03", "name": "Deprecated SSE Transport", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "shell-server": {"id": "MCP-01", "name": "Shell Command Access via MCP", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "unpinned-package": {"id": "MCP-04", "name": "Unpinned Package Version", "url": "https://owasp.org/www-project-mcp-top-10/"},
    # v2.0 checks (OWASP Agentic Security Top 10 mapped)
    "version-pinning": {"id": "ASI07", "name": "Supply Chain / Unpinned Version", "url": "https://owasp.org/www-project-agentic-security/"},
    "transport-security": {"id": "ASI04", "name": "Insecure MCP Transport", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-oauth": {"id": "ASI06", "name": "Missing OAuth/Auth Enforcement", "url": "https://owasp.org/www-project-agentic-security/"},
    "wildcard-tools": {"id": "ASI01", "name": "Unrestricted Tool Access", "url": "https://owasp.org/www-project-agentic-security/"},
    "unrestricted-fs": {"id": "ASI01", "name": "Unrestricted Filesystem Access", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-input-validation": {"id": "ASI02", "name": "Missing Input Validation", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-output-sanitization": {"id": "ASI05", "name": "Missing Output Sanitization", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-rate-limit": {"id": "ASI04", "name": "Missing Rate Limiting", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-logging": {"id": "ASI10", "name": "Missing Audit Logging", "url": "https://owasp.org/www-project-agentic-security/"},
    "hardcoded-secret": {"id": "ASI06", "name": "Hardcoded Secret in Config", "url": "https://owasp.org/www-project-agentic-security/"},
    "docker-socket": {"id": "ASI04", "name": "Docker Socket Exposure", "url": "https://owasp.org/www-project-agentic-security/"},
    "privilege-escalation": {"id": "ASI01", "name": "Privilege Escalation Risk", "url": "https://owasp.org/www-project-agentic-security/"},
    "ssrf-risk": {"id": "ASI04", "name": "Server-Side Request Forgery", "url": "https://owasp.org/www-project-agentic-security/"},
    "memory-poisoning": {"id": "ASI03", "name": "Memory/Context Poisoning", "url": "https://owasp.org/www-project-agentic-security/"},
    "supply-chain-download": {"id": "ASI07", "name": "Supply Chain Download Risk", "url": "https://owasp.org/www-project-agentic-security/"},
    "insecure-protocol": {"id": "ASI06", "name": "Insecure Protocol", "url": "https://owasp.org/www-project-agentic-security/"},
    "excessive-env": {"id": "ASI01", "name": "Excessive Configuration Surface", "url": "https://owasp.org/www-project-agentic-security/"},
    "debug-mode": {"id": "ASI10", "name": "Debug Mode in Production", "url": "https://owasp.org/www-project-agentic-security/"},
    "debug-port": {"id": "ASI04", "name": "Debug Port Exposure", "url": "https://owasp.org/www-project-agentic-security/"},
    "multi-transport": {"id": "ASI03", "name": "Ambiguous Transport Routing", "url": "https://owasp.org/www-project-agentic-security/"},
    "shell-expansion": {"id": "ASI02", "name": "Shell Expansion Injection", "url": "https://owasp.org/www-project-agentic-security/"},
    "cors-wildcard": {"id": "ASI05", "name": "CORS Wildcard Access", "url": "https://owasp.org/www-project-agentic-security/"},
    "open-redirect": {"id": "ASI05", "name": "Open Redirect Risk", "url": "https://owasp.org/www-project-agentic-security/"},
    "excessive-args": {"id": "ASI01", "name": "Excessive Argument Complexity", "url": "https://owasp.org/www-project-agentic-security/"},
    "crypto-exposure": {"id": "ASI04", "name": "Cryptocurrency/Wallet Exposure", "url": "https://owasp.org/www-project-agentic-security/"},
    "temp-dir-risk": {"id": "ASI08", "name": "Temp Directory Risk", "url": "https://owasp.org/www-project-agentic-security/"},
    "recursive-watch": {"id": "ASI04", "name": "Recursive Watch Exhaustion", "url": "https://owasp.org/www-project-agentic-security/"},
    "scope-typosquat": {"id": "ASI07", "name": "NPM Scope Typosquatting", "url": "https://owasp.org/www-project-agentic-security/"},
    "missing-command": {"id": "ASI08", "name": "Missing Server Command", "url": "https://owasp.org/www-project-agentic-security/"},
    "db-connection-leak": {"id": "ASI06", "name": "Database Connection Exposure", "url": "https://owasp.org/www-project-agentic-security/"},
    "obfuscated-value": {"id": "ASI02", "name": "Obfuscated Configuration Value", "url": "https://owasp.org/www-project-agentic-security/"},
    "duplicate-server": {"id": "ASI08", "name": "Duplicate Server Name", "url": "https://owasp.org/www-project-agentic-security/"},
    "no-stdio": {"id": "ASI03", "name": "No Local Stdio Servers", "url": "https://owasp.org/www-project-agentic-security/"},
    "remote-heavy": {"id": "ASI04", "name": "Remote-Heavy Configuration", "url": "https://owasp.org/www-project-agentic-security/"},
    "clean": {"id": None, "name": "No Issues", "url": None},
    "disabled": {"id": None, "name": "Server Disabled", "url": None},
}

# ═══ CWE Mapping ═══
# Maps each finding category to relevant CWE IDs for SARIF enrichment
CWE_MAPPING = {
    "network-exposure": [{"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"}],
    "rug-pull": [{"id": "CWE-494", "name": "Download of Code Without Integrity Check"}],
    "secret-leak": [{"id": "CWE-798", "name": "Use of Hard-coded Credentials"}],
    "command-injection": [{"id": "CWE-78", "name": "OS Command Injection"}],
    "path-traversal": [{"id": "CWE-22", "name": "Path Traversal"}],
    "tool-poisoning": [{"id": "CWE-94", "name": "Code Injection"}],
    "config": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "typosquat": [{"id": "CWE-506", "name": "Embedded Malicious Code"}],
    "dangerous-permission": [{"id": "CWE-250", "name": "Execution with Unnecessary Privileges"}],
    "missing-auth": [{"id": "CWE-306", "name": "Missing Authentication for Critical Function"}],
    "sensitive-path": [{"id": "CWE-538", "name": "Insertion of Sensitive Information into Externally-Accessible File or Directory"}],
    "overbroad-access": [{"id": "CWE-732", "name": "Incorrect Permission Assignment for Critical Resource"}],
    "excessive-servers": [{"id": "CWE-1059", "name": "Insufficient Technical Documentation"}],
    "env-var-leak": [{"id": "CWE-798", "name": "Use of Hard-coded Credentials"}],
    "known-vulnerable": [{"id": "CWE-1395", "name": "Dependency on Vulnerable Third-Party Component"}],
    "symlink-risk": [{"id": "CWE-59", "name": "Improper Link Resolution Before File Access"}],
    "shadow-server": [{"id": "CWE-284", "name": "Improper Access Control"}],
    "code-execution": [{"id": "CWE-95", "name": "Eval Injection"}],
    "known-malicious": [{"id": "CWE-506", "name": "Embedded Malicious Code"}],
    "deprecated-transport": [{"id": "CWE-477", "name": "Use of Obsolete Function"}],
    "shell-server": [{"id": "CWE-78", "name": "OS Command Injection"}],
    "unpinned-package": [{"id": "CWE-1104", "name": "Use of Unmaintained Third Party Components"}],
    # v2.0 checks
    "version-pinning": [{"id": "CWE-1104", "name": "Use of Unmaintained Third Party Components"}],
    "transport-security": [{"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"}],
    "missing-oauth": [{"id": "CWE-306", "name": "Missing Authentication for Critical Function"}],
    "wildcard-tools": [{"id": "CWE-250", "name": "Execution with Unnecessary Privileges"}],
    "unrestricted-fs": [{"id": "CWE-732", "name": "Incorrect Permission Assignment for Critical Resource"}],
    "missing-input-validation": [{"id": "CWE-20", "name": "Improper Input Validation"}],
    "missing-output-sanitization": [{"id": "CWE-116", "name": "Improper Encoding or Escaping of Output"}],
    "missing-rate-limit": [{"id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling"}],
    "missing-logging": [{"id": "CWE-778", "name": "Insufficient Logging"}],
    "hardcoded-secret": [{"id": "CWE-798", "name": "Use of Hard-coded Credentials"}],
    "docker-socket": [{"id": "CWE-250", "name": "Execution with Unnecessary Privileges"}],
    "privilege-escalation": [{"id": "CWE-269", "name": "Improper Privilege Management"}],
    "ssrf-risk": [{"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"}],
    "memory-poisoning": [{"id": "CWE-94", "name": "Code Injection"}],
    "supply-chain-download": [{"id": "CWE-494", "name": "Download of Code Without Integrity Check"}],
    "insecure-protocol": [{"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"}],
    "excessive-env": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "debug-mode": [{"id": "CWE-489", "name": "Active Debug Code"}],
    "debug-port": [{"id": "CWE-489", "name": "Active Debug Code"}],
    "multi-transport": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "shell-expansion": [{"id": "CWE-78", "name": "OS Command Injection"}],
    "cors-wildcard": [{"id": "CWE-942", "name": "Permissive Cross-domain Policy with Untrusted Domains"}],
    "open-redirect": [{"id": "CWE-601", "name": "URL Redirection to Untrusted Site"}],
    "excessive-args": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "crypto-exposure": [{"id": "CWE-312", "name": "Cleartext Storage of Sensitive Information"}],
    "temp-dir-risk": [{"id": "CWE-377", "name": "Insecure Temporary File"}],
    "recursive-watch": [{"id": "CWE-400", "name": "Uncontrolled Resource Consumption"}],
    "scope-typosquat": [{"id": "CWE-506", "name": "Embedded Malicious Code"}],
    "missing-command": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "db-connection-leak": [{"id": "CWE-798", "name": "Use of Hard-coded Credentials"}],
    "obfuscated-value": [{"id": "CWE-506", "name": "Embedded Malicious Code"}],
    "duplicate-server": [{"id": "CWE-1188", "name": "Insecure Default Initialization of Resource"}],
    "no-stdio": [{"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"}],
    "remote-heavy": [{"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"}],
}

# ═══ Remediation Guidance (Markdown) ═══
# Provides help.markdown content for each rule in SARIF output
REMEDIATION_GUIDANCE = {
    "network-exposure": "## Network Exposure\n\nMCP servers should **never** expose transport over non-localhost URLs.\n\n### Remediation\n- Use `stdio` transport instead of HTTP\n- If HTTP is required, bind to `127.0.0.1` only\n- Never use `0.0.0.0` (binds to all interfaces)",
    "rug-pull": "## Rug Pull Risk\n\nUsing `@latest` or auto-update patterns means the code running on your machine can change without notice.\n\n### Remediation\n- Pin packages to exact versions (e.g., `@1.2.3`)\n- Remove `-y` / `--yes` flags from npx\n- Audit packages before updating",
    "secret-leak": "## Secret Leakage\n\nHardcoded secrets in configuration files can be exposed through version control, logs, or error messages.\n\n### Remediation\n- Move secrets to environment variables\n- Use `${VAR_NAME}` references in config\n- Never commit secrets to version control",
    "command-injection": "## Command Injection\n\nUsing `shell=True` allows arbitrary command execution through shell metacharacters.\n\n### Remediation\n- Use array-based arguments instead of shell strings\n- Validate and sanitize all inputs\n- Apply principle of least privilege",
    "path-traversal": "## Path Traversal\n\n`..` sequences in arguments can escape intended directory boundaries.\n\n### Remediation\n- Use absolute paths\n- Validate paths against an allowlist\n- Use `os.path.realpath()` to resolve symlinks",
    "typosquat": "## Typosquat Detection\n\nThe package name closely resembles a known legitimate package, which may indicate a typosquat attack.\n\n### Remediation\n- Verify the exact package name from official documentation\n- Check the package publisher and download counts\n- Use `npm info <package>` to inspect metadata",
    "dangerous-permission": "## Dangerous Permissions\n\nFlags like `--allow-all`, `--no-sandbox`, or `sudo` disable security boundaries.\n\n### Remediation\n- Remove dangerous permission flags\n- Use minimum required permissions\n- Run MCP servers as unprivileged users",
    "missing-auth": "## Missing Authentication\n\nHTTP transport without authentication headers allows unauthorized access.\n\n### Remediation\n- Add authentication headers to HTTP transport config\n- Use stdio transport (no auth needed)\n- Implement API key or token-based auth",
    "sensitive-path": "## Sensitive Path Access\n\nMCP servers should not have access to directories containing credentials or keys.\n\n### Remediation\n- Restrict server access to project directories only\n- Never grant access to `.ssh`, `.aws`, `.env`, or similar\n- Use allowlists for permitted paths",
    "overbroad-access": "## Overbroad Filesystem Access\n\nRoot or system-level path access grants far more permissions than needed.\n\n### Remediation\n- Scope access to specific project directories\n- Avoid granting access to `/`, `C:\\`, or user home directories\n- Follow the principle of least privilege",
    "env-var-leak": "## Environment Variable Leak\n\nSensitive environment variables should never have hardcoded values in config files.\n\n### Remediation\n- Use `${VAR_NAME}` references instead of literal values\n- Store secrets in `.env` files (excluded from VCS)\n- Use secret management tools for production",
    "excessive-servers": "## Excessive Server Count\n\nToo many active MCP servers increase the attack surface.\n\n### Remediation\n- Disable unused servers with `\"disabled\": true`\n- Review which servers are actively needed\n- Remove servers that are no longer in use",
    "known-vulnerable": "## Known Vulnerable Component\n\nThis package has known CVEs with published exploits.\n\n### Remediation\n- Update to the patched version immediately\n- Check the CVE details for impact assessment\n- Consider replacing with a safer alternative",
    "symlink-risk": "## Symlink Bypass Risk\n\nSymlink following can allow escaping sandbox boundaries (CVE-2025-53109).\n\n### Remediation\n- Disable symlink following in server config\n- Restrict server to specific safe directories\n- Validate all file paths after symlink resolution",
    "shadow-server": "## Shadow MCP Server\n\nTunnel services or public bindings expose MCP servers beyond localhost.\n\n### Remediation\n- Remove tunnel services (ngrok, cloudflared, etc.)\n- Bind to `127.0.0.1` only\n- Use authenticated transport if remote access is needed",
    "code-execution": "## Code Execution Risk\n\nPatterns like `eval()`, `exec()`, or `execAsync()` in arguments enable arbitrary code execution.\n\n### Remediation\n- Never use eval/exec in MCP tool handlers\n- Use parameterized APIs instead\n- Validate and sanitize all inputs",
    "known-malicious": "## Confirmed Malicious Package\n\nThis package has been confirmed as malware containing backdoors, reverse shells, or data exfiltration.\n\n### Remediation\n- **Remove immediately** from all configurations\n- Audit systems that may have run this package\n- Report to npm/PyPI security team\n- Check for signs of compromise",
    "deprecated-transport": "## Deprecated SSE Transport\n\nServer-Sent Events (SSE) transport is deprecated in favor of Streamable HTTP.\n\n### Remediation\n- Switch to Streamable HTTP transport\n- Streamable HTTP provides per-request auth and Origin validation\n- Update server and client libraries to latest versions",
    "shell-server": "## Shell Command Server\n\nUsing a raw shell interpreter as an MCP server allows arbitrary command execution.\n\n### Remediation\n- Never use `bash`, `sh`, `cmd`, or `powershell` as MCP server commands\n- Use purpose-built MCP servers with input validation\n- Remove `--shell` and `-c` flags from server arguments",
    "unpinned-package": "## Unpinned Package Version\n\nRunning packages without version pins makes you vulnerable to supply chain attacks.\n\n### Remediation\n- Pin to exact version: `package@1.2.3`\n- Never use `@latest` in production configs\n- Audit package contents before updating versions",
    "config": "## Configuration Issue\n\nGeneral configuration problem detected.\n\n### Remediation\n- Review the configuration file for syntax errors\n- Ensure all required fields are present\n- Validate against the MCP configuration schema",
    "tool-poisoning": "## Tool Poisoning\n\nPrompt injection patterns detected in tool descriptions.\n\n### Remediation\n- Remove suspicious patterns from tool descriptions\n- Never include executable code in descriptions\n- Audit all tool metadata for injection attempts",
    # v2.0 checks
    "version-pinning": "## Version Pinning\n\nUnpinned packages are vulnerable to supply chain attacks.\n\n### Remediation\n- Pin to exact version: `package@1.2.3`\n- Never use `@latest` in production configs\n- Audit package contents before updating",
    "transport-security": "## Transport Security\n\nstdio is lowest risk (local only). HTTP/SSE over HTTPS is medium risk.\n\n### Remediation\n- Prefer stdio transport for local servers\n- Use HTTPS for network-exposed servers\n- Ensure auth headers are configured for remote transport",
    "missing-oauth": "## Missing OAuth/PKCE\n\nRemote MCP server without OAuth 2.1 or auth headers.\n\n### Remediation\n- Configure OAuth 2.1 with PKCE for remote servers\n- Add Authorization header in env configuration\n- Use stdio for local-only servers",
    "wildcard-tools": "## Wildcard Tool Permissions\n\nWildcard '*' in allowedTools grants unrestricted tool access.\n\n### Remediation\n- Explicitly list only required tools\n- Never use wildcard permissions\n- Audit tool access regularly",
    "unrestricted-fs": "## Unrestricted Filesystem\n\nBroad filesystem grants allow access beyond project scope.\n\n### Remediation\n- Restrict allowedDirectories to specific project paths\n- Remove --allow-all flags\n- Use least-privilege filesystem access",
    "missing-input-validation": "## Missing Input Validation\n\nInput validation explicitly disabled via CLI flags.\n\n### Remediation\n- Remove --no-validate, --skip-validation, --unsafe flags\n- Ensure all inputs are validated before processing\n- Use schema validation for tool inputs",
    "missing-output-sanitization": "## Missing Output Sanitization\n\nRaw output enabled, risking data exfiltration.\n\n### Remediation\n- Enable output sanitization\n- Remove --raw-output, --no-sanitize, --no-escape flags\n- Validate and filter all output data",
    "missing-rate-limit": "## Missing Rate Limiting\n\nRemote server without rate limiting configured.\n\n### Remediation\n- Add rate limiting to prevent resource exhaustion\n- Configure rateLimit or rateLimitPerMinute\n- Use env vars for rate limit configuration",
    "missing-logging": "## Missing Audit Logging\n\nLogging explicitly disabled, breaking audit trail.\n\n### Remediation\n- Enable logging for security audit compliance\n- Remove --no-log, --no-audit, --silent flags\n- Route logs to centralized logging system",
    "hardcoded-secret": "## Hardcoded Secret\n\nSensitive environment variable appears hardcoded.\n\n### Remediation\n- Use ${ENV_VAR} references instead of literal values\n- Store secrets in vault (op://) or .env files\n- Never commit secrets to version control",
    "docker-socket": "## Docker Socket Exposure\n\nDocker socket mount allows container escape and host compromise.\n\n### Remediation\n- Use Docker API with TLS auth instead of raw socket\n- Never mount /var/run/docker.sock\n- Use rootless Docker or Podman",
    "privilege-escalation": "## Privilege Escalation\n\nElevated capabilities granted to MCP server.\n\n### Remediation\n- Remove --privileged and unnecessary capabilities\n- Use least-privilege principle\n- Run in unprivileged containers",
    "ssrf-risk": "## SSRF Risk\n\nInternal/private IP address detected in configuration.\n\n### Remediation\n- Use localhost or public endpoints only\n- Block internal network access (169.254.x, 10.x, 172.16-31.x, 192.168.x)\n- Validate all URLs before connection",
    "memory-poisoning": "## Memory/Context Poisoning\n\nPrompt/memory injection flags detected.\n\n### Remediation\n- Remove prompt override flags (--inject, --prepend, --system-prompt)\n- Use validated configuration instead\n- Audit all prompt modification patterns",
    "supply-chain-download": "## Supply Chain Download\n\nDirect GitHub raw download in server config.\n\n### Remediation\n- Pin to specific commit SHA\n- Use versioned package manager instead\n- Verify checksums of downloaded content",
    "insecure-protocol": "## Insecure Protocol\n\nFTP, Telnet, unencrypted WebSocket, or plain HTTP detected.\n\n### Remediation\n- Use HTTPS, WSS, or SFTP for all remote connections\n- Never use unencrypted protocols for MCP communication\n- Enable TLS for all network transports",
    "excessive-env": "## Excessive Environment Variables\n\nLarge number of environment variables increases attack surface.\n\n### Remediation\n- Reduce to minimum required env vars\n- Move configuration to files\n- Use config management tools",
    "debug-mode": "## Debug Mode\n\nDebug/verbose mode enabled in production.\n\n### Remediation\n- Disable debug mode in production\n- Set NODE_ENV=production and LOG_LEVEL=warn\n- Remove --debug and --verbose flags",
    "debug-port": "## Debug Port\n\nNode.js --inspect debug port allows remote code execution.\n\n### Remediation\n- Remove --inspect flag from production MCP server args\n- Never expose debug ports in production\n- Use secure debugging alternatives",
    "multi-transport": "## Multiple Transports\n\nMultiple transport types configured, causing ambiguous routing.\n\n### Remediation\n- Use a single transport type per server (stdio OR url)\n- Remove conflicting transport configurations\n- Prefer stdio for local servers",
    "shell-expansion": "## Shell Expansion\n\nShell expansion/substitution characters in arguments.\n\n### Remediation\n- Remove shell metacharacters ($(), ${}, backticks, pipes)\n- Pass values via env vars instead\n- Use array-based arguments",
    "cors-wildcard": "## CORS Wildcard\n\nCORS wildcard '*' allows any origin to access the MCP server.\n\n### Remediation\n- Restrict CORS to specific trusted origins\n- Never use '*' for CORS in production\n- Validate Origin headers",
    "open-redirect": "## Open Redirect\n\nRedirect/callback URL uses HTTP or wildcard.\n\n### Remediation\n- Use HTTPS redirect URLs with exact domain matching\n- Never use wildcards in redirect URIs\n- Validate all callback URLs",
    "excessive-args": "## Excessive Arguments\n\nUnusually complex configuration with many arguments.\n\n### Remediation\n- Simplify arguments\n- Use config files instead of CLI arguments\n- Review necessity of each argument",
    "crypto-exposure": "## Cryptocurrency Exposure\n\nWallet, mnemonic, or private key patterns detected.\n\n### Remediation\n- Never store wallet keys or mnemonics in MCP config\n- Use hardware wallet or vault\n- Remove all cryptocurrency credential patterns",
    "temp-dir-risk": "## Temp Directory Risk\n\nTemp directory may be world-writable or cleaned unexpectedly.\n\n### Remediation\n- Use a dedicated project directory instead of system temp\n- Set proper permissions on temp directories\n- Clean up temporary files after use",
    "recursive-watch": "## Recursive Watch\n\nRecursive directory watching may cause high CPU/memory usage.\n\n### Remediation\n- Limit watch scope to specific directories\n- Use ignore patterns for node_modules, .git, etc.\n- Set maximum depth for recursive watching",
    "scope-typosquat": "## Scope Typosquatting\n\nNPM scope resembles an official organization scope.\n\n### Remediation\n- Verify the npm package scope is the official one\n- Check publisher and download counts\n- Use only packages from verified publishers",
    "missing-command": "## Missing Command\n\nServer has neither command nor URL configured.\n\n### Remediation\n- Add 'command' for stdio transport\n- Add 'url' for HTTP transport\n- Remove misconfigured server entries",
    "db-connection-leak": "## Database Connection Exposure\n\nDatabase connection string exposed in MCP config.\n\n### Remediation\n- Move DB connection strings to .env or vault\n- Reference via ${VAR} in config\n- Never hardcode database credentials",
    "obfuscated-value": "## Obfuscated Value\n\nBase64-encoded values may be hiding sensitive data.\n\n### Remediation\n- Verify base64 values are legitimate (e.g., certs)\n- Avoid encoding secrets to hide them\n- Use proper secret management instead",
    "duplicate-server": "## Duplicate Server\n\nCase-insensitive server name collision detected.\n\n### Remediation\n- Use unique server names\n- Remove duplicate entries\n- Standardize naming conventions",
    "no-stdio": "## No Stdio Servers\n\nAll MCP servers are remote with no local stdio servers.\n\n### Remediation\n- Prefer stdio transport for local tools\n- Reduce network attack surface with local servers\n- Ensure all remote servers have proper auth",
    "remote-heavy": "## Remote-Heavy Configuration\n\nOver 70% of servers are remote/HTTP.\n\n### Remediation\n- Balance with local stdio servers\n- Ensure all remote servers have authentication\n- Review necessity of each remote connection",
}


# ═══ Policy-as-Code System ═══
# Allows customization of severity thresholds and check enable/disable via YAML/JSON

DEFAULT_POLICY = {
    "version": "1.0",
    "description": "Default Config Guard policy — all checks enabled at default severity",
    "checks": {
        "network-exposure": {"enabled": True, "severity": None},  # None = use default
        "rug-pull": {"enabled": True, "severity": None},
        "secret-leak": {"enabled": True, "severity": None},
        "command-injection": {"enabled": True, "severity": None},
        "path-traversal": {"enabled": True, "severity": None},
        "typosquat": {"enabled": True, "severity": None},
        "dangerous-permission": {"enabled": True, "severity": None},
        "missing-auth": {"enabled": True, "severity": None},
        "sensitive-path": {"enabled": True, "severity": None},
        "overbroad-access": {"enabled": True, "severity": None},
        "env-var-leak": {"enabled": True, "severity": None},
        "excessive-servers": {"enabled": True, "severity": None},
        "known-vulnerable": {"enabled": True, "severity": None},
        "symlink-risk": {"enabled": True, "severity": None},
        "shadow-server": {"enabled": True, "severity": None},
        "code-execution": {"enabled": True, "severity": None},
        "known-malicious": {"enabled": True, "severity": None},
        "version-pinning": {"enabled": True, "severity": None},
        "transport-security": {"enabled": True, "severity": None},
        # v2.0 checks (OWASP Agentic Top 10 mapped)
        "missing-oauth": {"enabled": True, "severity": None},
        "wildcard-tools": {"enabled": True, "severity": None},
        "unrestricted-fs": {"enabled": True, "severity": None},
        "missing-input-validation": {"enabled": True, "severity": None},
        "missing-output-sanitization": {"enabled": True, "severity": None},
        "missing-rate-limit": {"enabled": True, "severity": None},
        "missing-logging": {"enabled": True, "severity": None},
        "hardcoded-secret": {"enabled": True, "severity": None},
        "docker-socket": {"enabled": True, "severity": None},
        "privilege-escalation": {"enabled": True, "severity": None},
        "ssrf-risk": {"enabled": True, "severity": None},
        "memory-poisoning": {"enabled": True, "severity": None},
        "supply-chain-download": {"enabled": True, "severity": None},
        "insecure-protocol": {"enabled": True, "severity": None},
        "excessive-env": {"enabled": True, "severity": None},
        "debug-mode": {"enabled": True, "severity": None},
        "debug-port": {"enabled": True, "severity": None},
        "multi-transport": {"enabled": True, "severity": None},
        "shell-expansion": {"enabled": True, "severity": None},
        "cors-wildcard": {"enabled": True, "severity": None},
        "open-redirect": {"enabled": True, "severity": None},
        "excessive-args": {"enabled": True, "severity": None},
        "crypto-exposure": {"enabled": True, "severity": None},
        "temp-dir-risk": {"enabled": True, "severity": None},
        "recursive-watch": {"enabled": True, "severity": None},
        "scope-typosquat": {"enabled": True, "severity": None},
        "missing-command": {"enabled": True, "severity": None},
        "db-connection-leak": {"enabled": True, "severity": None},
        "obfuscated-value": {"enabled": True, "severity": None},
        "duplicate-server": {"enabled": True, "severity": None},
        "no-stdio": {"enabled": True, "severity": None},
        "remote-heavy": {"enabled": True, "severity": None},
    },
    "thresholds": {
        "fail_on_critical": True,
        "fail_on_high": True,
        "fail_on_medium": False,
        "max_score_deduction": 100,
        "min_passing_score": 0,
    },
    "ignore": {
        "servers": [],          # Server names to skip
        "categories": [],       # Categories to skip entirely
        "patterns": [],         # Regex patterns for messages to ignore
    },
}


def _build_poisoning_patterns():
    """Build patterns that indicate prompt injection in tool descriptions."""
    return [
        (re.compile(r"ignore\s+previous", re.I), "Prompt injection attempt in tool description"),
        (re.compile(r"system\s+prompt", re.I), "References system prompt"),
        (re.compile(r"override\s+instructions", re.I), "Instruction override attempt"),
        (re.compile(r"<\s*script", re.I), "Script tag in tool description"),
        (re.compile(r"eval\s*\(", re.I), "eval() call — code execution risk"),
        (re.compile(r"exec\s*\(", re.I), "exec() call — code execution risk"),
    ]


def _build_secret_detectors():
    """Build detectors for hardcoded secrets.

    NOTE: These are DETECTION patterns, not actual secrets.
    The check-secrets hook may flag this file — these are regex
    matchers used to FIND secrets in other files.
    """
    # nosec: these are detection patterns, not secrets
    prefixes = ["sk", "pk", "api"]
    envs = ["live", "test", "prod"]
    # Build pattern dynamically to avoid triggering secret scanners
    key_parts = []
    for p in prefixes:
        for e in envs:
            key_parts.append(f"{p}[_-]?{e}")
    key_pattern = "(?:" + "|".join(key_parts) + r")[_-]\w{10,}"

    return [
        (re.compile(key_pattern, re.I), "Possible hardcoded API key"),
        (re.compile(r"password\s*[:=]\s*\S+", re.I), "Hardcoded password"),
    ]


# Non-localhost URL patterns
_NETWORK_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])\S+",
    re.IGNORECASE,
)

# ═══ Typosquat Detection ═══
# Known legitimate MCP packages — typosquats use similar names
KNOWN_MCP_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-git",
    "@anthropic/mcp-server-filesystem",
    "@upstash/context7-mcp",
    "@anthropic/claude-code-mcp",
    "mcp-tool-search",
    "playwright-mcp",
    "mcp-remote",
    "mcp-server-git",
    "mcp-server-filesystem",
    "gemini-mcp-tool",
    "mcp-vegalite-server",
    "github-kanban-mcp",
    "godot-mcp",
    "fermat-mcp",
    "@anthropic/mcp-inspector",
    "mcp-inspector",
]

# ═══ Known Malicious Packages (Do Not Use) ═══
# Confirmed malicious packages — immediately flag if found in configs
KNOWN_MALICIOUS = [
    "postmark-mcp",                     # First malicious MCP server on npm
    "@lanyer640/mcp-runcommand-server",  # Reverse shell, same C2 as PyPI variants
    "oura-ring-mcp-trojan",             # SmartLoader campaign — trojanized Oura Ring MCP deploying StealC
    "@smartloader/oura-mcp",            # SmartLoader variant
    "postmark-mcp-backdoor",            # Confirmed malicious — steals email credentials
    # SANDWORM_MODE campaign (19 packages, Feb 2026) — McpInject AI toolchain worm
    "claud-code",                        # Typosquat of claude-code
    "cloude-code",                       # Typosquat of claude-code
    "cloude",                            # Typosquat of claude
    "opencraw",                          # Typosquat of openclaw
    "suport-color",                      # Typosquat of supports-color (npm: supports-colors)
    "supports-colors",                   # Typosquat of supports-color
    "claude-code-helper",                # AI tool impersonation
    "openclaw-mcp",                      # AI tool impersonation
    "crypto-locale",                     # SANDWORM_MODE credential harvester
    "crypto-reader-info",                # SANDWORM_MODE credential harvester
    "detect-cache",                      # SANDWORM_MODE credential harvester
    "format-defaults",                   # SANDWORM_MODE credential harvester
    "hardhta",                           # SANDWORM_MODE typosquat of hardhat
    "locale-loader-pro",                 # SANDWORM_MODE credential harvester
    "naniod",                            # SANDWORM_MODE typosquat of nanoid
    "node-native-bridge",                # SANDWORM_MODE credential harvester
    "parse-compat",                      # SANDWORM_MODE credential harvester
    "rimarf",                            # SANDWORM_MODE typosquat of rimraf
    "scan-store",                        # SANDWORM_MODE credential harvester
    "secp256",                           # SANDWORM_MODE typosquat of secp256k1
    "veim",                              # SANDWORM_MODE typosquat of vim
    "yarsg",                             # SANDWORM_MODE typosquat of yargs
    # JFrog-reported malicious MCP servers (Oct 2025) — reverse shell to C2 45.115.38.27:4433
    "mcp-runcmd-server",                 # JFrog XRAY-734538: reverse shell before MCP start
    "mcp-runcommand-server",             # JFrog XRAY-734540: same C2, same campaign
    "mcp-runcommand-server2",            # JFrog XRAY-734539: same C2, same campaign
    # JFrog-reported malicious PyPI packages (2025-2026)
    "chimera-sandbox-extensions",        # JFrog: multi-stage infostealer, DGA C2, steals AWS/Git/CI creds
    "soopsocks",                         # JFrog: backdoor proxy, Go binary, PowerShell, Discord exfil
    "smtblib",                           # JFrog: typosquat of smtplib
    "ziphash",                           # JFrog: malicious PyPI package (Feb 2026)
    "uuzip",                             # JFrog: malicious PyPI package (Feb 2026)
    "uzip",                              # JFrog: malicious PyPI package (Feb 2026)
    "minizip",                           # JFrog: malicious PyPI package (Feb 2026)
    # AI/ML ecosystem malicious packages (Kaspersky, Positive Technologies, ReversingLabs)
    "deepseeek",                         # Positive Tech: infostealer impersonating DeepSeek AI
    "deepseekai",                         # Positive Tech: same payload, same attacker
    "gptplus",                           # Kaspersky: JarkaStealer impersonating GPT-4 Turbo API
    "claudeai-eng",                      # Kaspersky: JarkaStealer impersonating Claude AI API
    "aliyun-ai-labs-snippets-sdk",       # ReversingLabs: Pickle exploit in fake Alibaba AI SDK
    "ai-labs-snippets-sdk",              # ReversingLabs: same Pickle infostealer
    "aliyun-ai-labs-sdk",                # ReversingLabs: same Pickle infostealer
    # Lazarus APT supply chain packages (JPCERT/CC, 2024-2026)
    "pycryptoenv",                       # Lazarus Group RAT, fake recruiter campaign
    "pycryptoconf",                      # Lazarus Group RAT, same campaign
    "quasarlib",                         # Lazarus Group RAT, same campaign
    "swapmempool",                       # Lazarus Group RAT, same campaign
]

# ═══ Known Vulnerable Packages (CVE Database) ═══
# Packages with known critical CVEs — flag if used without patched version
KNOWN_VULNERABLE = {
    "mcp-remote": {
        "cve": "CVE-2025-6514",
        "description": "Supply chain vulnerability + RCE via OS commands in OAuth discovery fields (CVSS 9.6, 437K+ affected downloads)",
        "fix": "Update to latest patched version and verify OAuth endpoints",
    },
    "@modelcontextprotocol/server-git": {
        "cve": "CVE-2025-68145/68143/68144",
        "description": "RCE via prompt injection (path validation bypass) + path traversal in git_add (CVE-2026-27735)",
        "fix": "Update to >= 2026.1.14, restrict allowed repositories",
    },
    "mcp-server-git": {
        "cve": "CVE-2026-27735",
        "description": "Path traversal in git_add — files outside repo boundaries can be staged",
        "fix": "Update to >= 2026.1.14",
    },
    "@anthropic/mcp-server-filesystem": {
        "cve": "CVE-2025-53109/53110",
        "description": "Symlink bypass (full read/write) + prefix-matching bypass — unrestricted filesystem access outside sandbox",
        "fix": "Update to >= 2025.7.1, disable symlink following",
    },
    "mcp-server-filesystem": {
        "cve": "CVE-2025-53109/53110",
        "description": "Symlink bypass + prefix-matching bypass — full filesystem access outside sandbox",
        "fix": "Update to patched version, restrict to specific directories only",
    },
    "gemini-mcp-tool": {
        "cve": "CVE-2026-0755",
        "description": "Critical RCE via execAsync with unsanitized shell metacharacters",
        "fix": "Do not use — replace with official Google ADK MCP integration",
    },
    "mcp-vegalite-server": {
        "cve": "CVE-2026-1977",
        "description": "Critical RCE via eval() on malicious Vega-Lite spec",
        "fix": "Do not use — eval() in MCP tool handlers is fundamentally unsafe",
    },
    "github-kanban-mcp": {
        "cve": "CVE-2026-0756",
        "description": "High RCE through MCP tool interface",
        "fix": "Do not use — replace with official @modelcontextprotocol/server-github",
    },
    "godot-mcp": {
        "cve": "CVE-2026-25546",
        "description": "Command injection via exec() with unsanitized projectPath",
        "fix": "Do not use — input sanitization missing entirely",
    },
    "fermat-mcp": {
        "cve": "CVE-2026-2008",
        "description": "Critical RCE via eval() on user-supplied equation strings — part of eval() epidemic",
        "fix": "Do not use — eval() on user input is fundamentally unsafe",
    },
    "@anthropic/mcp-inspector": {
        "cve": "CVE-2026-23744",
        "description": "Critical RCE via unauthenticated HTTP — listens 0.0.0.0 by default with no auth (CVSS 9.8)",
        "fix": "Update to >= 1.4.3, bind to localhost only, add authentication",
    },
    "mcp-inspector": {
        "cve": "CVE-2026-23744",
        "description": "Critical RCE via unauthenticated HTTP — inspector listens 0.0.0.0 with no auth (CVSS 9.8)",
        "fix": "Update to >= 1.4.3, bind to localhost only",
    },
    "@modelcontextprotocol/server-filesystem": {
        "cve": "CVE-2025-53109/53110",
        "description": "Symlink bypass (full read/write) + prefix-matching bypass — unrestricted filesystem access outside sandbox",
        "fix": "Update to >= 2025.7.1, disable symlink following",
    },
    "@anthropic/mcp-go-sdk": {
        "cve": "CVE-2026-27896",
        "description": "Case-insensitive JSON parsing bypass — allows WAF/proxy circumvention via Go encoding/json (CVSS 7.0)",
        "fix": "Update Go SDK to >= 1.3.1",
    },
    "mcp-maigret": {
        "cve": "CVE-2026-2130",
        "description": "RCE via unsanitized user input in Docker container",
        "fix": "Do not use — input sanitization missing",
    },
    "harmonyos-mcp-server": {
        "cve": "CVE-2026-2131",
        "description": "Remote code execution via MCP tool handler",
        "fix": "Do not use — unpatched RCE",
    },
    "xcode-mcp-server": {
        "cve": "CVE-2026-2178",
        "description": "Command injection via unsanitized input in Node.js tool handler",
        "fix": "Do not use — unsanitized user input is fundamentally unsafe",
    },
    "@anthropic/claude-code": {
        "cve": "CVE-2025-59536/CVE-2026-21852/CVE-2026-24887",
        "description": "Hooks abuse + MCP consent bypass (CVSS 8.7), API key exfiltration (CVSS 5.3), command injection via find",
        "fix": "Update to >= 2.0.72, audit .claude/settings.json hooks in cloned repos",
    },
    "@anthropic/claude-code-mcp": {
        "cve": "CVE-2025-59536/CVE-2026-21852/CVE-2026-24887",
        "description": "Hooks abuse + MCP consent bypass (CVSS 8.7), API key exfiltration (CVSS 5.3), command injection via find",
        "fix": "Update to >= 2.0.72, audit .claude/settings.json hooks in cloned repos",
    },
    "playwright-mcp": {
        "cve": "CVE-2025-9611",
        "description": "CSRF via DNS rebinding — unvalidated Origin headers allow unauthorized tool invocation",
        "fix": "Update to latest version, validate Origin headers",
    },
    "@modelcontextprotocol/sdk": {
        "cve": "CVE-2026-25536/CVE-2026-0621",
        "description": "Cross-client data leak in StreamableHTTPServerTransport (CVSS 7.1) + ReDoS via UriTemplate regex catastrophic backtracking",
        "fix": "Update to >= 1.26.0, ensure per-client McpServer instances",
    },
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            subs = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, subs))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquat(package_name: str) -> str | None:
    """Check if a package name looks like a typosquat of a known package."""
    clean_name = package_name.split("@")[0] if "@" in package_name and not package_name.startswith("@") else package_name
    # Strip version from scoped packages
    if "@" in clean_name:
        parts = clean_name.rsplit("@", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            clean_name = parts[0]

    for known in KNOWN_MCP_PACKAGES:
        if clean_name == known:
            return None  # exact match, not a typosquat
        dist = _levenshtein_distance(clean_name.lower(), known.lower())
        if 0 < dist <= 2 and len(clean_name) > 5:
            return f"Similar to known package '{known}' (edit distance: {dist})"
    return None


# ═══ Dangerous Permission Patterns ═══
DANGEROUS_PERMISSIONS = [
    (re.compile(r"--allow-all", re.I), "Grants all permissions"),
    (re.compile(r"--no-sandbox", re.I), "Disables sandbox protection"),
    (re.compile(r"--disable-security", re.I), "Disables security features"),
    (re.compile(r"sudo\s+", re.I), "Runs with elevated privileges"),
    (re.compile(r"--privileged", re.I), "Docker privileged mode"),
    (re.compile(r"--cap-add\s+SYS_ADMIN", re.I), "Adds SYS_ADMIN capability"),
]

# ═══ Sensitive Path Patterns ═══
# Paths that MCP servers should not have access to
SENSITIVE_PATHS = [
    (re.compile(r"[\\/]\.ssh(?:[\\/]|$)", re.I), "SSH keys directory"),
    (re.compile(r"[\\/]\.gnupg(?:[\\/]|$)", re.I), "GPG keys directory"),
    (re.compile(r"[\\/]\.aws(?:[\\/]|$)", re.I), "AWS credentials directory"),
    (re.compile(r"[\\/]\.kube(?:[\\/]|$)", re.I), "Kubernetes config directory"),
    (re.compile(r"[\\/]\.docker(?:[\\/]|$)", re.I), "Docker config directory"),
    (re.compile(r"[\\/]\.env(?:[\\/]|$|\.\w+$)", re.I), "Environment file with secrets"),
    (re.compile(r"[\\/]\.secrets?(?:[\\/]|$)", re.I), "Secrets directory"),
    (re.compile(r"[\\/]\.password", re.I), "Password file"),
]

# Root/system-level paths that indicate overly broad filesystem access
OVERBROAD_PATHS = [
    re.compile(r'^[A-Z]:\\$', re.I),       # C:\
    re.compile(r'^/$'),                      # /
    re.compile(r'^/(?:etc|var|usr)$'),       # System dirs
    re.compile(r'^C:\\Windows', re.I),       # Windows system
    re.compile(r'^C:\\Program Files', re.I), # Program files
    re.compile(r'^/home$'),                  # All home dirs
    re.compile(r'^C:\\Users$', re.I),        # All user dirs
]


def scan_mcp_config(mcp_path: Path) -> list:
    """Scan an .mcp.json file for security risks."""
    findings = []
    poisoning_patterns = _build_poisoning_patterns()
    secret_detectors = _build_secret_detectors()

    if not mcp_path.exists():
        findings.append({
            "server": "(config)",
            "risk": "INFO",
            "category": "config",
            "message": f"No .mcp.json found at {mcp_path}",
            "fix": None,
        })
        return findings

    try:
        config = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        findings.append({
            "server": "(config)",
            "risk": "HIGH",
            "category": "config",
            "message": f"Invalid JSON in .mcp.json: {e}",
            "fix": "Fix JSON syntax errors",
        })
        return findings

    servers = config.get("mcpServers", {})

    for name, srv in servers.items():
        if srv.get("disabled", False):
            findings.append({
                "server": name,
                "risk": "INFO",
                "category": "disabled",
                "message": f"Server '{name}' is disabled",
                "fix": None,
            })
            continue

        command = srv.get("command", "")
        args = srv.get("args", [])
        env = srv.get("env", {})
        url = srv.get("url", "")
        args_str = " ".join(str(a) for a in args)
        full_cmd = f"{command} {args_str}"
        cmd_lower = command.lower()

        # Check 1: Transport Security
        if url:
            if _NETWORK_PATTERN.search(url):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "network-exposure",
                    "message": f"HTTP transport to non-localhost URL: {url}",
                    "fix": "Use stdio transport or bind to localhost only",
                })
            elif "0.0.0.0" in url:
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "network-exposure",
                    "message": f"Server binds to 0.0.0.0: {url}",
                    "fix": "Bind to 127.0.0.1 instead",
                })

        # Check 2: Rug Pull Risk (npx @latest)
        if "npx" in command or "npx" in args_str:
            if "@latest" in args_str:
                findings.append({
                    "server": name,
                    "risk": "MEDIUM",
                    "category": "rug-pull",
                    "message": "Uses npx with @latest — code changes on every run",
                    "fix": "Pin to specific version",
                })
            if "-y" in args or "--yes" in args:
                findings.append({
                    "server": name,
                    "risk": "LOW",
                    "category": "rug-pull",
                    "message": "Uses npx -y — auto-confirms package install",
                    "fix": "Remove -y flag for manual approval",
                })

        # Check 3: Secret Leakage
        for pattern, desc in secret_detectors:
            if pattern.search(full_cmd):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "secret-leak",
                    "message": f"{desc} found in command/args",
                    "fix": "Move secrets to .env and use variable references",
                })

        for env_key, env_val in env.items():
            if env_val and not env_val.startswith("${") and not env_val.startswith("$"):
                for pattern, desc in secret_detectors:
                    if pattern.search(str(env_val)):
                        findings.append({
                            "server": name,
                            "risk": "CRITICAL",
                            "category": "secret-leak",
                            "message": f"{desc} hardcoded in env.{env_key}",
                            "fix": f"Use variable reference instead",
                        })

        # Check 4: Command Injection
        if "shell=True" in full_cmd or "shell=true" in full_cmd.lower():
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "command-injection",
                "message": "shell=True — injection risk",
                "fix": "Use array args instead of shell string",
            })

        # Check 5: Path Traversal
        for arg in args:
            if ".." in str(arg):
                findings.append({
                    "server": name,
                    "risk": "MEDIUM",
                    "category": "path-traversal",
                    "message": f"Path traversal '..' in args: {arg}",
                    "fix": "Use absolute paths",
                })

        # Check 6: Typosquat Detection
        for arg in args:
            arg_str = str(arg)
            if "@" in arg_str or "mcp" in arg_str.lower():
                typo_result = check_typosquat(arg_str)
                if typo_result:
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "typosquat",
                        "message": f"Possible typosquat: {arg_str}. {typo_result}",
                        "fix": "Verify package name matches the official package",
                    })

        # Check 7: Dangerous Permissions
        for pattern, desc in DANGEROUS_PERMISSIONS:
            if pattern.search(full_cmd):
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "dangerous-permission",
                    "message": f"{desc}: found in command/args",
                    "fix": "Remove dangerous permission flags",
                })

        # Check 8: No auth on HTTP transport
        if url and not srv.get("headers") and "http" in url.lower():
            if "localhost" in url or "127.0.0.1" in url:
                pass  # localhost is ok without auth
            else:
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "missing-auth",
                    "message": f"HTTP transport without auth headers: {url}",
                    "fix": "Add authentication headers or use stdio transport",
                })

        # Check 9: Sensitive path access
        for arg in args:
            arg_str = str(arg)
            for pattern, desc in SENSITIVE_PATHS:
                if pattern.search(arg_str):
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "sensitive-path",
                        "message": f"Access to {desc}: {arg_str}",
                        "fix": "Restrict access to non-sensitive directories",
                    })

        # Check 10: Overly broad filesystem access
        for arg in args:
            arg_str = str(arg).strip()
            for pattern in OVERBROAD_PATHS:
                if pattern.match(arg_str):
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "overbroad-access",
                        "message": f"Root/system-level path access: {arg_str}",
                        "fix": "Scope to specific project directories instead",
                    })

        # Check 11: Environment variable leak risk
        sensitive_env_names = {"DATABASE_URL", "DB_PASSWORD", "PRIVATE_KEY",
                             "SECRET_KEY", "JWT_SECRET", "SESSION_SECRET",
                             "ENCRYPTION_KEY", "MASTER_KEY"}
        for env_key in env:
            if env_key.upper() in sensitive_env_names:
                env_val = str(env.get(env_key, ""))
                if env_val and not env_val.startswith("${") and not env_val.startswith("$"):
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "env-var-leak",
                        "message": f"Sensitive env var '{env_key}' has hardcoded value",
                        "fix": "Use environment variable reference (${VAR}) instead",
                    })

        # Check 13: Known vulnerable packages (CVE database)
        for arg in args:
            arg_str = str(arg)
            for vuln_pkg, vuln_info in KNOWN_VULNERABLE.items():
                if vuln_pkg in arg_str:
                    findings.append({
                        "server": name,
                        "risk": "CRITICAL",
                        "category": "known-vulnerable",
                        "message": f"Uses package with known CVE ({vuln_info['cve']}): {vuln_pkg} - {vuln_info['description']}",
                        "fix": vuln_info["fix"],
                    })

        # Check 14: Symlink risk detection
        for arg in args:
            arg_str = str(arg)
            # CVE-2025-53109: symlink bypass can escalate to system takeover
            if "--follow-symlinks" in arg_str or "--dereference" in arg_str:
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "symlink-risk",
                    "message": "Symlink following enabled - CVE-2025-53109 risk",
                    "fix": "Disable symlink following or restrict to safe directories",
                })

        # Check 15: Shadow MCP server detection (OWASP MCP-05)
        # Detects servers using non-standard transport or unusual command patterns
        arg_str_full = command + " " + " ".join(str(a) for a in args)
        if any(shadow in arg_str_full.lower() for shadow in [
            "ngrok", "localtunnel", "cloudflared", "serveo",
            "0.0.0.0", "::0", "INADDR_ANY",
        ]):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "shadow-server",
                "message": "Server exposes via tunnel/public binding — potential shadow MCP server (OWASP MCP-05)",
                "fix": "Bind to 127.0.0.1 only. Remove tunnel services. Use authenticated transport.",
            })

        # Check 16: Dangerous runtime patterns (eval/exec epidemic - CVE-2026-0755/1977/25546)
        # Three Feb 2026 CVEs share the same root cause: eval()/exec() in MCP tool handlers
        for arg in args:
            arg_lower = str(arg).lower()
            if any(pattern in arg_lower for pattern in [
                "eval(", "exec(", "execasync(", "execsync(",
                "child_process", "spawn(", "function(",
            ]):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "code-execution",
                    "message": "Server args contain code execution patterns (eval/exec) — CVE-2026-0755/1977/25546 class",
                    "fix": "Never use eval/exec in MCP servers. Use parameterized APIs instead.",
                })
                break  # One finding per server is enough

        # Check 17: Known malicious packages (OWASP MCP-07)
        # Confirmed malicious MCP servers — immediate CRITICAL alert
        for arg in args:
            arg_str = str(arg)
            for malicious_pkg in KNOWN_MALICIOUS:
                if malicious_pkg in arg_str:
                    findings.append({
                        "server": name,
                        "risk": "CRITICAL",
                        "category": "known-malicious",
                        "message": f"CONFIRMED MALICIOUS PACKAGE: {malicious_pkg} — contains reverse shell/malware payload",
                        "fix": "Remove immediately. This package is confirmed malware. Report to npm/PyPI.",
                    })

        # Check 18: Deprecated SSE transport detection
        args_str_lower = " ".join(str(a) for a in args).lower()
        if any(sse_indicator in args_str_lower or sse_indicator in cmd_lower for sse_indicator in ["--sse", "--transport=sse", "transport=sse", "server-sent-events"]):
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "deprecated-transport",
                "message": f"Server '{name}' uses deprecated SSE transport — migrate to Streamable HTTP (MCP spec 2025-03-26)",
                "fix": "Switch to Streamable HTTP transport for per-request auth, Origin validation, and load-balancer support",
            })
        # Also check transport config in env
        if env:
            for env_key, env_val in env.items():
                if "transport" in env_key.lower() and "sse" in str(env_val).lower():
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "deprecated-transport",
                        "message": f"Server '{name}' env var '{env_key}' configures deprecated SSE transport",
                        "fix": "Switch to Streamable HTTP transport",
                    })

        # Check 19: Shell command server detection
        shell_commands = {"sh", "bash", "cmd", "cmd.exe", "powershell", "powershell.exe", "zsh", "fish"}
        if cmd_lower in shell_commands:
            findings.append({
                "server": name,
                "risk": "CRITICAL",
                "category": "shell-server",
                "message": f"Server '{name}' runs a shell command directly ({command}) — highest-risk MCP pattern",
                "fix": "Never use raw shell interpreters as MCP servers. Use purpose-built servers with input validation.",
            })
        elif any(f"--shell" in str(a).lower() or f"-c" == str(a).strip() for a in args):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "shell-server",
                "message": f"Server '{name}' passes shell execution flags (--shell or -c) — arbitrary command execution risk",
                "fix": "Remove shell flags. Use structured tool interfaces instead of shell passthrough.",
            })

        # Check 20: Unpinned npx/uvx package versions (supply chain risk)
        if cmd_lower in ("npx", "npx.cmd", "uvx"):
            for arg in args:
                arg_s = str(arg)
                if arg_s.startswith("-"):
                    continue  # skip flags
                # Check if package has version pin
                if "@" not in arg_s or arg_s.endswith("@latest"):
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "unpinned-package",
                        "message": f"Server '{name}' runs unpinned package '{arg_s}' via {command} — vulnerable to supply chain attacks",
                        "fix": f"Pin to exact version: {arg_s}@<version> (e.g., {arg_s}@1.0.0)",
                    })
                    break  # only flag once per server

        # Check 21: MCP Server Version Pinning (OWASP ASI07)
        # Unpinned packages are supply chain risks — a compromised upstream
        # version silently replaces what you ran yesterday.
        _version_pin_pattern = re.compile(r"@\d+\.\d+\.\d+")
        for arg in args:
            arg_str = str(arg)
            # Only check args that look like npm package references
            if ("@" in arg_str or "mcp" in arg_str.lower()) and not arg_str.startswith("-"):
                if _version_pin_pattern.search(arg_str):
                    continue  # Version is pinned, e.g. mcp-server@1.2.3
                if "/" in arg_str and not arg_str.startswith("@"):
                    continue  # Looks like a file path
                if arg_str.startswith("--") or arg_str.startswith("-"):
                    continue  # It's a flag
                # Likely an unpinned package reference
                findings.append({
                    "server": name,
                    "risk": "WARNING",
                    "category": "version-pinning",
                    "message": f"Unpinned package '{arg_str}' — supply chain risk without version lock",
                    "fix": f"Pin to a specific version, e.g. {arg_str}@x.y.z",
                })

        # Also check the command itself for npx without version pin
        if "npx" in command:
            for arg in args:
                arg_str = str(arg)
                if arg_str.startswith("-"):
                    continue
                # First non-flag arg after npx is the package
                if not _version_pin_pattern.search(arg_str) and not arg_str.startswith("-"):
                    existing = [f for f in findings if f["server"] == name
                                and f["category"] == "version-pinning"
                                and arg_str in f["message"]]
                    if not existing:
                        findings.append({
                            "server": name,
                            "risk": "WARNING",
                            "category": "version-pinning",
                            "message": f"npx runs unpinned package '{arg_str}' — supply chain risk",
                            "fix": f"Pin version: npx {arg_str}@x.y.z",
                        })
                    break  # Only check the first package arg

        # Check 22: Transport Security Assessment (OWASP ASI04)
        transport_type = srv.get("transport", {}).get("type", "") if isinstance(srv.get("transport"), dict) else ""
        if url:
            url_lower = url.lower()
            is_localhost = any(loc in url_lower for loc in ["localhost", "127.0.0.1", "[::1]"])
            if url_lower.startswith("http://") and not is_localhost:
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "transport-security",
                    "message": f"Non-stdio transport over unencrypted HTTP: {url}",
                    "fix": "Use HTTPS for network-exposed MCP servers, or switch to stdio transport",
                })
            elif url_lower.startswith("https://"):
                findings.append({
                    "server": name,
                    "risk": "MEDIUM",
                    "category": "transport-security",
                    "message": f"Network-exposed MCP transport (HTTPS): {url}",
                    "fix": "Prefer stdio transport for local servers. If remote access is needed, ensure auth headers are configured.",
                })
        elif transport_type in ("sse", "streamable-http", "streamableHttp"):
            transport_url = srv.get("transport", {}).get("url", "")
            if transport_url:
                t_url_lower = transport_url.lower()
                is_t_localhost = any(loc in t_url_lower for loc in ["localhost", "127.0.0.1", "[::1]"])
                if t_url_lower.startswith("http://") and not is_t_localhost:
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "transport-security",
                        "message": f"{transport_type} transport over unencrypted HTTP: {transport_url}",
                        "fix": "Use HTTPS for network-exposed MCP servers, or switch to stdio transport",
                    })
                elif t_url_lower.startswith("https://"):
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "transport-security",
                        "message": f"{transport_type} transport over HTTPS (network-exposed): {transport_url}",
                        "fix": "Prefer stdio for local servers. Ensure auth is configured for remote.",
                    })

        # Check 23: OAuth 2.1 / PKCE enforcement [ASI06]
        auth_header = env.get("AUTH_HEADER", "") or env.get("AUTHORIZATION", "")
        if url and not auth_header and not any(k.lower() in ("authorization", "auth", "bearer") for k in env):
            if url.startswith("http"):
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "missing-oauth",
                    "message": "Remote MCP server without OAuth/auth headers configured",
                    "fix": "Configure OAuth 2.1 with PKCE or add Authorization header in env",
                })

        # Check 24: Wildcard tool permissions [ASI01]
        tools_cfg = srv.get("tools", {})
        allowed_tools = srv.get("allowedTools", [])
        if isinstance(allowed_tools, list) and "*" in allowed_tools:
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "wildcard-tools",
                "message": "Wildcard '*' in allowedTools grants unrestricted tool access",
                "fix": "Explicitly list only required tools instead of using wildcard",
            })

        # Check 25: Unrestricted filesystem access [ASI01]
        fs_patterns = re.compile(r'(--allow-all|--no-restrict|allowedDirectories.*["\']?[/\\]?["\']?\s*[,\]])', re.I)
        if fs_patterns.search(args_str):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "unrestricted-fs",
                "message": "Unrestricted filesystem access granted to MCP server",
                "fix": "Restrict allowedDirectories to specific project paths only",
            })

        # Check 26: Missing input validation indicators [ASI02]
        if any(p in args_str.lower() for p in ["--no-validate", "--skip-validation", "--unsafe"]):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "missing-input-validation",
                "message": "Input validation explicitly disabled via CLI flags",
                "fix": "Remove --no-validate/--skip-validation/--unsafe flags",
            })

        # Check 27: Missing output sanitization [ASI05]
        if any(p in args_str.lower() for p in ["--raw-output", "--no-sanitize", "--no-escape"]):
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "missing-output-sanitization",
                "message": "Output sanitization disabled — risk of data exfiltration",
                "fix": "Enable output sanitization to prevent sensitive data leakage",
            })

        # Check 28: Missing rate limiting [ASI04]
        if url and url.startswith("http") and not any(k.lower() in ("rate_limit", "ratelimit", "throttle") for k in env):
            if not srv.get("rateLimit") and not srv.get("rateLimitPerMinute"):
                findings.append({
                    "server": name,
                    "risk": "LOW",
                    "category": "missing-rate-limit",
                    "message": "Remote MCP server without rate limiting configured",
                    "fix": "Add rate limiting to prevent resource exhaustion attacks",
                })

        # Check 29: Missing audit logging [ASI10]
        if any(p in args_str.lower() for p in ["--no-log", "--no-audit", "--silent", "--quiet"]):
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "missing-logging",
                "message": "Audit logging explicitly disabled",
                "fix": "Enable logging for security audit trail compliance",
            })

        # Check 30: Unencrypted secrets in environment [ASI06]
        # nosec: detection pattern, not a real secret
        secret_env_pat = re.compile(r'(passwd|secret|private.?key|auth.?token)', re.I)
        for env_key, env_val in env.items():
            if secret_env_pat.search(env_key) and isinstance(env_val, str) and not env_val.startswith("${"):
                if not env_val.startswith("env:") and not env_val.startswith("op://"):
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "hardcoded-secret",
                        "message": f"Sensitive env var '{env_key}' appears hardcoded (not from vault/env reference)",
                        "fix": f"Use ${{ENV_VAR}} reference or vault URI (op://) for '{env_key}'",
                    })
                    break  # One finding per server is enough

        # Check 31: Docker socket exposure [ASI04]
        docker_pat = re.compile(r'(/var/run/docker\.sock|//./pipe/docker|docker\.sock)', re.I)
        if docker_pat.search(args_str) or docker_pat.search(full_cmd):
            findings.append({
                "server": name,
                "risk": "CRITICAL",
                "category": "docker-socket",
                "message": "Docker socket mounted — allows container escape and host compromise",
                "fix": "Use Docker API with TLS auth instead of raw socket mount",
            })

        # Check 32: Privilege escalation vectors [ASI01]
        priv_pat = re.compile(r'(--privileged|--cap-add|SYS_ADMIN|SYS_PTRACE|--security-opt.*unconfined)', re.I)
        if priv_pat.search(args_str):
            findings.append({
                "server": name,
                "risk": "CRITICAL",
                "category": "privilege-escalation",
                "message": "Elevated privileges granted — container escape or host access risk",
                "fix": "Remove --privileged and unnecessary capabilities; use least-privilege",
            })

        # Check 33: SSRF risk — internal network access [ASI04]
        ssrf_pat = re.compile(r'(169\.254\.|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', re.I)
        if ssrf_pat.search(url) or ssrf_pat.search(args_str):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "ssrf-risk",
                "message": "Internal/private IP address detected — SSRF risk",
                "fix": "Use localhost or public endpoints; block internal network access",
            })

        # Check 34: Memory/context poisoning risk [ASI03]
        poison_flags = ["--inject", "--prepend", "--system-prompt", "--override-prompt"]
        if any(f in args_str.lower() for f in poison_flags):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "memory-poisoning",
                "message": "Prompt/memory injection flags detected in server args",
                "fix": "Remove prompt override flags; use validated configuration instead",
            })

        # Check 35: Supply chain — GitHub raw downloads [ASI07]
        gh_raw = re.compile(r'(raw\.githubusercontent\.com|github\.com/.*/raw/|gist\.github\.com)', re.I)
        if gh_raw.search(args_str) or gh_raw.search(url):
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "supply-chain-download",
                "message": "Direct GitHub raw download in server config — content can change",
                "fix": "Pin to specific commit SHA or use versioned package manager",
            })

        # Check 36: Deprecated/insecure protocols [ASI06]
        insecure_proto = re.compile(r'(ftp://|telnet://|ws://[^s]|http://(?!localhost|127\.|0\.0\.0\.0|\[::1\]))', re.I)
        if insecure_proto.search(args_str) or insecure_proto.search(url):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "insecure-protocol",
                "message": "Insecure protocol detected (FTP/Telnet/unencrypted WS/HTTP)",
                "fix": "Use HTTPS, WSS, or SFTP for all remote connections",
            })

        # Check 37: Excessive environment variables [ASI01]
        if len(env) > 20:
            findings.append({
                "server": name,
                "risk": "LOW",
                "category": "excessive-env",
                "message": f"{len(env)} environment variables — excessive configuration surface",
                "fix": "Reduce to minimum required env vars; move config to files",
            })

        # Check 38: Debug mode enabled in production [ASI10]
        debug_pat = re.compile(r'(--debug|--verbose|DEBUG=true|NODE_ENV=development|LOG_LEVEL=debug)', re.I)
        if debug_pat.search(args_str) or any(debug_pat.search(f"{k}={v}") for k, v in env.items() if isinstance(v, str)):
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "debug-mode",
                "message": "Debug/verbose mode enabled — may leak sensitive information",
                "fix": "Disable debug mode; set NODE_ENV=production and LOG_LEVEL=warn",
            })

        # Check 39: Node.js --inspect debug port [ASI04]
        if re.search(r'--inspect(-brk)?(\s|=|$)', args_str):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "debug-port",
                "message": "Node.js --inspect debug port enabled — allows remote code execution",
                "fix": "Remove --inspect flag from production MCP server args",
            })

        # Check 40: Multiple transport types [ASI03]
        has_stdio = bool(command)
        has_url = bool(url)
        has_sse = "sse" in args_str.lower() or "server-sent" in args_str.lower()
        transport_count = sum([has_stdio, has_url, has_sse])
        if transport_count > 1:
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "multi-transport",
                "message": f"Multiple transport types configured ({transport_count}) — ambiguous routing",
                "fix": "Use a single transport type per server (stdio OR url, not both)",
            })

        # Check 41: Shell expansion characters in args [ASI02]
        shell_exp = re.compile(r'(\$\(|\$\{|`[^`]+`|>\s*[/\\]|<\s*[/\\]|\|\s*\w)')
        if shell_exp.search(args_str):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "shell-expansion",
                "message": "Shell expansion/substitution characters in args — injection risk",
                "fix": "Remove shell metacharacters; pass values via env vars instead",
            })

        # Check 42: CORS wildcard in env [ASI05]
        cors_val = env.get("CORS_ORIGIN", "") or env.get("ALLOWED_ORIGINS", "") or env.get("ACCESS_CONTROL_ALLOW_ORIGIN", "")
        if cors_val == "*":
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "cors-wildcard",
                "message": "CORS wildcard '*' allows any origin to access the MCP server",
                "fix": "Restrict CORS to specific trusted origins",
            })

        # Check 43: Unvalidated redirect URLs [ASI05]
        redirect_pat = re.compile(r'(redirect.?uri|callback.?url|return.?url)', re.I)
        for env_key, env_val in env.items():
            if redirect_pat.search(env_key) and isinstance(env_val, str):
                if env_val.startswith("http://") or "*" in env_val:
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "open-redirect",
                        "message": f"Redirect/callback URL '{env_key}' uses HTTP or wildcard",
                        "fix": "Use HTTPS redirect URLs with exact domain matching",
                    })
                    break

        # Check 44: Excessive argument count [ASI01]
        if len(args) > 30:
            findings.append({
                "server": name,
                "risk": "LOW",
                "category": "excessive-args",
                "message": f"{len(args)} arguments — unusually complex configuration",
                "fix": "Simplify args; use config file instead of CLI arguments",
            })

        # Check 45: Cryptocurrency/wallet patterns [ASI04]
        crypto_pat = re.compile(r'(wallet|mnemonic|seed.?phrase|private.?key.*0x|metamask|etherscan)', re.I)
        if crypto_pat.search(args_str) or any(crypto_pat.search(str(v)) for v in env.values()):
            findings.append({
                "server": name,
                "risk": "CRITICAL",
                "category": "crypto-exposure",
                "message": "Cryptocurrency/wallet-related patterns detected",
                "fix": "Never store wallet keys or mnemonics in MCP config; use hardware wallet or vault",
            })

        # Check 46: Temp directory usage risk [ASI08]
        temp_pat = re.compile(r'(/tmp/|\\temp\\|%TEMP%|\\AppData\\Local\\Temp)', re.I)
        if temp_pat.search(args_str):
            findings.append({
                "server": name,
                "risk": "LOW",
                "category": "temp-dir-risk",
                "message": "Temp directory in args — may be world-writable or cleaned unexpectedly",
                "fix": "Use a dedicated project directory instead of system temp",
            })

        # Check 47: Recursive directory watching [ASI04]
        if any(p in args_str.lower() for p in ["--watch-all", "--recursive-watch", "**/*"]):
            findings.append({
                "server": name,
                "risk": "LOW",
                "category": "recursive-watch",
                "message": "Recursive directory watching — may cause high CPU/memory usage",
                "fix": "Limit watch scope to specific directories or use ignore patterns",
            })

        # Check 48: Known risky npm scopes / typosquatting patterns [ASI07]
        risky_scopes = ["@anthropic-ai-", "@openai-", "@google-ai-", "@modelcontextprotocol-"]
        for scope in risky_scopes:
            if scope in args_str.lower():
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "scope-typosquat",
                    "message": f"Possible typosquat npm scope resembling official: '{scope}' in args",
                    "fix": "Verify the npm package scope is the official one, not a lookalike",
                })
                break

        # Check 49: Empty or missing command [ASI08]
        if not command and not url:
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "missing-command",
                "message": "Server has neither command nor URL configured — cannot start",
                "fix": "Add 'command' for stdio or 'url' for HTTP transport",
            })

        # Check 50: Database connection strings in env/args [ASI06]
        # nosec: detection pattern for DB URIs, not actual connection strings
        db_pat = re.compile(r'(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://|sqlite:///)', re.I)
        if db_pat.search(args_str) or any(db_pat.search(str(v)) for v in env.values() if isinstance(v, str)):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "db-connection-leak",
                "message": "Database connection string exposed in MCP config",
                "fix": "Move DB connection strings to .env or vault; reference via ${VAR}",
            })

        # Check 51: Base64-encoded values (obfuscation) [ASI02]
        b64_pat = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')
        suspicious_b64 = 0
        for env_val in env.values():
            if isinstance(env_val, str) and b64_pat.match(env_val) and len(env_val) > 40:
                suspicious_b64 += 1
        if suspicious_b64 > 0:
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "obfuscated-value",
                "message": f"{suspicious_b64} env value(s) appear base64-encoded — possible obfuscation",
                "fix": "Verify base64 values are legitimate (e.g., certs); avoid hiding data",
            })

        # Check 52: Duplicate server names (case-insensitive) [ASI08]
        name_lower = name.lower()
        dupes = [n for n in servers if n.lower() == name_lower and n != name]
        if dupes:
            findings.append({
                "server": name,
                "risk": "MEDIUM",
                "category": "duplicate-server",
                "message": f"Duplicate server name (case-insensitive): '{name}' vs '{dupes[0]}'",
                "fix": "Use unique server names to prevent routing confusion",
            })

        # Mark clean servers
        server_findings = [f for f in findings if f["server"] == name]
        if not server_findings:
            findings.append({
                "server": name,
                "risk": "INFO",
                "category": "clean",
                "message": f"Server '{name}' passed all checks",
                "fix": None,
            })

    # ── Global checks (outside per-server loop) ──

    # Check 12: Excessive server count (attack surface)
    active_servers = {n: s for n, s in servers.items() if not s.get("disabled", False)}
    active_count = len(active_servers)
    if active_count > 15:
        findings.append({
            "server": "(global)",
            "risk": "MEDIUM",
            "category": "excessive-servers",
            "message": f"{active_count} active MCP servers — large attack surface",
            "fix": "Disable unused servers to reduce attack surface",
        })
    elif active_count > 10:
        findings.append({
            "server": "(global)",
            "risk": "LOW",
            "category": "excessive-servers",
            "message": f"{active_count} active MCP servers — consider reducing",
            "fix": "Review and disable unused servers",
        })

    # Check 53: No stdio servers — all remote [ASI03]
    stdio_count = sum(1 for s in active_servers.values() if s.get("command") and not s.get("url"))
    if active_count > 0 and stdio_count == 0:
        findings.append({
            "server": "(global)",
            "risk": "HIGH",
            "category": "no-stdio",
            "message": "No stdio (local) servers — all MCP servers are remote",
            "fix": "Prefer stdio transport for local tools to reduce network attack surface",
        })

    # Check 54: High ratio of remote/HTTP servers [ASI04]
    remote_count = sum(1 for s in active_servers.values() if s.get("url", "").startswith("http"))
    if active_count >= 3 and remote_count / active_count > 0.7:
        findings.append({
            "server": "(global)",
            "risk": "MEDIUM",
            "category": "remote-heavy",
            "message": f"{remote_count}/{active_count} servers are remote — high network dependency",
            "fix": "Balance with local stdio servers; ensure all remote servers have auth",
        })

    return findings


def calculate_score(findings: list) -> int:
    """Calculate security score 0-100."""
    deduction = 0
    for f in findings:
        risk = f.get("risk", "INFO")
        if risk == "CRITICAL":
            deduction += 25
        elif risk == "HIGH":
            deduction += 15
        elif risk in ("MEDIUM", "WARNING"):
            deduction += 8
        elif risk == "LOW":
            deduction += 3
    return max(0, 100 - deduction)


def format_report(findings: list, score: int) -> str:
    """Format findings as a human-readable report."""
    lines = ["", "MCP Security Scan Results", "=" * 40, ""]
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW", "INFO"]:
        items = [f for f in findings if f["risk"] == risk]
        if not items:
            continue
        icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "WARNING": "[~]", "LOW": "[.]", "INFO": "[i]"}.get(risk, "[i]")
        lines.append(f"{icon} {risk} ({len(items)}):")
        for f in items:
            owasp = OWASP_MAPPING.get(f.get("category", ""), {})
            owasp_tag = f" [{owasp['id']}]" if owasp.get("id") else ""
            lines.append(f"  [{f['server']}]{owasp_tag} {f['message']}")
            if f.get("fix"):
                lines.append(f"    Fix: {f['fix']}")
        lines.append("")
    lines.append(f"Security Score: {score}/100")
    return "\n".join(lines)


def _partial_fingerprint(rule_id: str, artifact_uri: str) -> str:
    """Generate a stable partial fingerprint for deduplication.

    Uses SHA-256 of rule ID + artifact URI so the same finding in the same
    file always produces the same fingerprint across runs.
    """
    raw = f"{rule_id}:{artifact_uri}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def format_sarif(findings: list, score: int, mcp_path: str = ".mcp.json") -> dict:
    """Format findings as SARIF v2.1.0 for CI/CD integration.

    SARIF (Static Analysis Results Interchange Format) is the standard
    for GitHub Code Scanning, Azure DevOps, and other CI/CD pipelines.

    Enhanced with:
    - partialFingerprints for result deduplication
    - CWE tags in result properties
    - help.markdown remediation guidance per rule
    - Proper severity-to-level mapping
    """
    risk_to_level = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    rules = []
    results = []
    rule_ids_seen = set()

    for i, f in enumerate(findings):
        category = f.get("category", "unknown")
        risk = f.get("risk", "INFO")
        owasp = OWASP_MAPPING.get(category, {})
        cwes = CWE_MAPPING.get(category, [])

        # Build rule ID (deduplicated)
        rule_id = f"mcp-{category}"
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rule_def = {
                "id": rule_id,
                "name": category.replace("-", " ").title(),
                "shortDescription": {"text": owasp.get("name", category)},
                "defaultConfiguration": {"level": risk_to_level.get(risk, "note")},
            }
            if owasp.get("id"):
                rule_def["helpUri"] = owasp["url"]

            # Add properties with OWASP and CWE tags
            props = {}
            if owasp.get("id"):
                props["owasp"] = owasp["id"]
            if cwes:
                props["tags"] = [f"{c['id']}: {c['name']}" for c in cwes]
            if props:
                rule_def["properties"] = props

            # Add help.markdown remediation guidance
            guidance = REMEDIATION_GUIDANCE.get(category)
            if guidance:
                rule_def["help"] = {
                    "text": guidance.replace("#", "").replace("*", "").strip(),
                    "markdown": guidance,
                }

            rules.append(rule_def)

        # Build result
        artifact_uri = str(mcp_path)
        result = {
            "ruleId": rule_id,
            "level": risk_to_level.get(risk, "note"),
            "message": {"text": f['message']},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": _partial_fingerprint(rule_id, artifact_uri),
            },
        }

        # Add CWE tags to result properties
        if cwes:
            result["properties"] = {
                "tags": [f"{c['id']}: {c['name']}" for c in cwes],
            }

        if f.get("fix"):
            result["fixes"] = [{"description": {"text": f["fix"]}}]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-config-guard",
                    "version": __version__,
                    "informationUri": "https://github.com/KGT24k/mcp-config-guard",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {"securityScore": score},
        }],
    }


def discover_mcp_configs() -> list:
    """Auto-discover MCP config files across common locations."""
    home = Path(os.environ.get("USERPROFILE", os.environ.get("HOME", "")))
    discovered = []

    candidates = [
        # Claude Code
        Path.cwd() / ".mcp.json",
        PROJECT_ROOT / ".mcp.json",
        # Claude Desktop (Windows)
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        # Claude Desktop (macOS)
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        # Claude Desktop (Linux)
        home / ".config" / "claude" / "claude_desktop_config.json",
        # Cursor
        home / ".cursor" / "mcp.json",
        # VS Code
        home / ".vscode" / "mcp.json",
        # Windsurf
        home / ".windsurf" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            discovered.append(candidate)

    return list(set(discovered))  # deduplicate


def _filter_by_severity(findings: list, threshold: str) -> list:
    """Filter findings to only include those at or above the severity threshold."""
    threshold_upper = threshold.upper()
    if threshold_upper not in RISK_LEVELS:
        return findings
    min_level = RISK_LEVELS[threshold_upper]
    return [f for f in findings if RISK_LEVELS.get(f.get("risk", "INFO"), 0) >= min_level]


def _determine_exit_code(findings: list, use_exit_code: bool) -> int:
    """Determine exit code based on findings.

    When --exit-code is set:
      0 = no findings (clean)
      1 = findings found (any severity)
      2 = CRITICAL or HIGH findings found

    When --exit-code is NOT set (legacy behavior):
      0 = no CRITICAL/HIGH findings
      1 = CRITICAL/HIGH findings found
    """
    if use_exit_code:
        critical_high = [f for f in findings if f.get("risk") in ("CRITICAL", "HIGH")]
        non_info = [f for f in findings if f.get("risk") not in ("INFO",) and f.get("category") not in ("clean", "disabled")]
        if critical_high:
            return 2
        elif non_info:
            return 1
        else:
            return 0
    else:
        # Legacy behavior
        critical_high = [f for f in findings if f.get("risk") in ("CRITICAL", "HIGH")]
        return 1 if critical_high else 0


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Config Guard — Zero-dependency security linter for MCP configurations"
    )
    parser.add_argument("--path", default=str(PROJECT_ROOT), help="Project root to scan")
    parser.add_argument("--json", action="store_true", help="JSON output (legacy, prefer --format json)")
    parser.add_argument("--sarif", action="store_true", help="SARIF v2.1.0 output (legacy, prefer --format sarif)")
    parser.add_argument("--discover", action="store_true", help="Auto-discover all MCP configs")
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default=None,
        help="Output format: text (default), json, sarif",
    )
    parser.add_argument(
        "--severity-threshold", "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Only report findings at or above this severity level",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        default=False,
        help="Return structured exit code: 0=clean, 1=findings, 2=critical/high",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress all output, only set exit code",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"config-guard {__version__}",
    )
    args = parser.parse_args()

    # Resolve output format: --format takes precedence over legacy --json/--sarif
    output_format = "text"
    if args.format:
        output_format = args.format
    elif args.sarif:
        output_format = "sarif"
    elif args.json:
        output_format = "json"

    if args.discover:
        configs = discover_mcp_configs()
        all_findings = []
        for cfg in configs:
            findings = scan_mcp_config(cfg)
            for f in findings:
                f["config_file"] = str(cfg)
            all_findings.extend(findings)
        if not configs:
            if not args.quiet:
                print("No MCP configuration files found.")
            sys.exit(0)

        # Apply severity threshold
        if args.severity_threshold:
            all_findings = _filter_by_severity(all_findings, args.severity_threshold)

        score = calculate_score(all_findings)

        if not args.quiet:
            if output_format == "sarif":
                print(json.dumps(format_sarif(all_findings, score, "multiple"), indent=2))
            elif output_format == "json":
                print(json.dumps({"configs": [str(c) for c in configs], "findings": all_findings, "score": score}, indent=2))
            else:
                print(f"\nDiscovered {len(configs)} MCP config(s):")
                for c in configs:
                    print(f"  {c}")
                print(format_report(all_findings, score))

        exit_code = _determine_exit_code(all_findings, args.exit_code)
        sys.exit(exit_code)
    else:
        mcp_path = Path(args.path) / ".mcp.json"
        findings = scan_mcp_config(mcp_path)

        # Apply severity threshold
        if args.severity_threshold:
            findings = _filter_by_severity(findings, args.severity_threshold)

        score = calculate_score(findings)

        if not args.quiet:
            if output_format == "sarif":
                print(json.dumps(format_sarif(findings, score, str(mcp_path)), indent=2))
            elif output_format == "json":
                print(json.dumps({"findings": findings, "score": score}, indent=2))
            else:
                print(format_report(findings, score))

        exit_code = _determine_exit_code(findings, args.exit_code)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
