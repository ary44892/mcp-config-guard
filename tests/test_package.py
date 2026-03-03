"""Tests for config-guard as standalone PyPI package.

Verifies:
1. Package imports correctly
2. Version is set
3. Core API functions exist
4. CLI entry point works
5. Zero dependencies (only stdlib)
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

# Load from package source
PKG_SRC = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(PKG_SRC))

import config_guard


class TestPackageMetadata:
    def test_version_set(self):
        assert hasattr(config_guard, "__version__")
        assert config_guard.__version__ == "2.0.0"

    def test_no_external_dependencies(self):
        """Config Guard must be zero-dependency (stdlib only)."""
        import ast
        source = (PKG_SRC / "config_guard" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module.split(".")[0])

        stdlib_modules = {
            "json", "os", "re", "sys", "pathlib", "argparse",
            "importlib", "collections", "typing", "abc", "functools",
            "itertools", "math", "string", "textwrap", "hashlib",
            "io",
        }
        for imp in imports:
            assert imp in stdlib_modules, f"Non-stdlib import: {imp}"


class TestCoreAPI:
    def test_scan_mcp_config_exists(self):
        assert callable(config_guard.scan_mcp_config)

    def test_calculate_score_exists(self):
        assert callable(config_guard.calculate_score)

    def test_format_report_exists(self):
        assert callable(config_guard.format_report)

    def test_format_sarif_exists(self):
        assert callable(config_guard.format_sarif)

    def test_discover_mcp_configs_exists(self):
        assert callable(config_guard.discover_mcp_configs)

    def test_main_exists(self):
        assert callable(config_guard.main)


class TestCoreScanning:
    def test_clean_config_scores_100(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["dist/index.js"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            score = config_guard.calculate_score(findings)
            assert score == 100

    def test_rug_pull_detected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "risky": {"command": "npx", "args": ["-y", "@some/pkg@latest"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            rugs = [f for f in findings if f["category"] == "rug-pull"]
            assert len(rugs) >= 1

    def test_sarif_output_valid(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "test": {"command": "node", "args": ["server.js"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            score = config_guard.calculate_score(findings)
            sarif = config_guard.format_sarif(findings, score)
            assert "sarif-schema-2.1.0" in sarif["$schema"]
            assert sarif["version"] == "2.1.0"

    def test_known_vulnerable_db(self):
        assert len(config_guard.KNOWN_VULNERABLE) >= 20
        assert "mcp-remote" in config_guard.KNOWN_VULNERABLE

    def test_owasp_mapping_complete(self):
        required = ["network-exposure", "rug-pull", "secret-leak", "command-injection",
                     "typosquat", "dangerous-permission", "known-vulnerable", "shadow-server",
                     "deprecated-transport", "shell-server", "unpinned-package"]
        for cat in required:
            assert cat in config_guard.OWASP_MAPPING


class TestCLI:
    def test_main_clean_exit(self):
        """Clean config should exit 0."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--json"]
            try:
                config_guard.main()
            except SystemExit as e:
                assert e.code == 0

    def test_main_critical_exit_1(self):
        """Critical findings should exit 1."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "bad": {"command": "npx", "args": ["mcp-remote", "--transport", "http://evil.com"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--json"]
            try:
                config_guard.main()
            except SystemExit as e:
                assert e.code == 1


# ═══ Helper: scan a config dict without writing to disk ═══
def _scan_config(config):
    """Helper to scan a config dict via temp file."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / ".mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")
        return config_guard.scan_mcp_config(p)


class TestCheck18DeprecatedSSE:
    """Check 18: Deprecated SSE transport detection."""

    def test_sse_flag_in_args(self):
        """Detect deprecated SSE transport via --sse flag."""
        config = {"mcpServers": {"old-server": {"command": "node", "args": ["server.js", "--sse"]}}}
        findings = _scan_config(config)
        categories = [f["category"] for f in findings]
        assert "deprecated-transport" in categories

    def test_transport_sse_in_args(self):
        """Detect --transport=sse in args."""
        config = {"mcpServers": {"old": {"command": "node", "args": ["server.js", "--transport=sse"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "deprecated-transport" for f in findings)

    def test_sse_in_env_transport_var(self):
        """Detect SSE configured via env var."""
        config = {"mcpServers": {"old": {"command": "node", "args": ["server.js"], "env": {"MCP_TRANSPORT": "sse"}}}}
        findings = _scan_config(config)
        assert any(f["category"] == "deprecated-transport" for f in findings)

    def test_streamable_http_no_flag(self):
        """Non-SSE transport should not trigger."""
        config = {"mcpServers": {"new": {"command": "node", "args": ["server.js", "--transport=streamable-http"]}}}
        findings = _scan_config(config)
        assert not any(f["category"] == "deprecated-transport" for f in findings)


class TestCheck19ShellServer:
    """Check 19: Shell command server detection."""

    def test_bash_as_command(self):
        """Detect raw shell interpreters as MCP servers."""
        config = {"mcpServers": {"shell": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        assert any(f["category"] == "shell-server" and f["risk"] == "CRITICAL" for f in findings)

    def test_cmd_exe_as_command(self):
        """Detect cmd.exe as MCP server."""
        config = {"mcpServers": {"shell": {"command": "cmd.exe", "args": []}}}
        findings = _scan_config(config)
        assert any(f["category"] == "shell-server" and f["risk"] == "CRITICAL" for f in findings)

    def test_powershell_as_command(self):
        """Detect powershell as MCP server."""
        config = {"mcpServers": {"shell": {"command": "powershell", "args": []}}}
        findings = _scan_config(config)
        assert any(f["category"] == "shell-server" and f["risk"] == "CRITICAL" for f in findings)

    def test_shell_flag_in_args(self):
        """Detect --shell flag in args."""
        config = {"mcpServers": {"risky": {"command": "node", "args": ["server.js", "--shell"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "shell-server" and f["risk"] == "HIGH" for f in findings)

    def test_dash_c_flag_in_args(self):
        """Detect -c flag in args."""
        config = {"mcpServers": {"risky": {"command": "node", "args": ["runner.js", "-c", "echo hello"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "shell-server" and f["risk"] == "HIGH" for f in findings)

    def test_node_server_no_shell(self):
        """Normal node server should not trigger shell detection."""
        config = {"mcpServers": {"safe": {"command": "node", "args": ["dist/index.js"]}}}
        findings = _scan_config(config)
        assert not any(f["category"] == "shell-server" for f in findings)


class TestCheck20UnpinnedPackage:
    """Check 20: Unpinned npx/uvx package versions."""

    def test_unpinned_npx_package(self):
        """Detect unpinned npx packages without version."""
        config = {"mcpServers": {"unpinned": {"command": "npx", "args": ["some-package"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "unpinned-package" for f in findings)

    def test_pinned_npx_passes(self):
        """Pinned npx packages should not trigger."""
        config = {"mcpServers": {"pinned": {"command": "npx", "args": ["some-package@1.0.0"]}}}
        findings = _scan_config(config)
        assert not any(f["category"] == "unpinned-package" for f in findings)

    def test_latest_tag_flagged(self):
        """@latest should still be flagged as unpinned."""
        config = {"mcpServers": {"latest": {"command": "npx", "args": ["some-package@latest"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "unpinned-package" for f in findings)

    def test_uvx_unpinned(self):
        """Detect unpinned uvx packages."""
        config = {"mcpServers": {"unpinned": {"command": "uvx", "args": ["some-tool"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "unpinned-package" for f in findings)

    def test_npx_flags_skipped(self):
        """Flags like -y should be skipped, package without version caught."""
        config = {"mcpServers": {"flagged": {"command": "npx", "args": ["-y", "some-package"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "unpinned-package" for f in findings)

    def test_node_command_not_flagged(self):
        """Non-npx/uvx commands should not trigger unpinned check."""
        config = {"mcpServers": {"safe": {"command": "node", "args": ["some-package"]}}}
        findings = _scan_config(config)
        assert not any(f["category"] == "unpinned-package" for f in findings)


class TestNewCVEs:
    """Verify new CVE entries are detected."""

    def test_new_cves_detected(self):
        """New CVE entries should be detected."""
        for pkg in ["mcp-maigret", "xcode-mcp-server", "harmonyos-mcp-server"]:
            config = {"mcpServers": {"test": {"command": "npx", "args": [pkg]}}}
            findings = _scan_config(config)
            assert any(f["category"] == "known-vulnerable" for f in findings), f"CVE not detected for {pkg}"

    def test_playwright_mcp_cve(self):
        """Playwright MCP server CVE should be detected."""
        config = {"mcpServers": {"pw": {"command": "npx", "args": ["playwright-mcp"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "known-vulnerable" for f in findings)

    def test_go_sdk_cve(self):
        """Go SDK CVE should be detected."""
        config = {"mcpServers": {"go": {"command": "npx", "args": ["@anthropic/mcp-go-sdk"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "known-vulnerable" for f in findings)

    def test_claude_code_cve(self):
        """Claude Code CVE should be detected."""
        config = {"mcpServers": {"cc": {"command": "npx", "args": ["@anthropic/claude-code"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "known-vulnerable" for f in findings)

    def test_known_vulnerable_count(self):
        """Should have at least 20 CVE entries."""
        assert len(config_guard.KNOWN_VULNERABLE) >= 20


class TestNewMaliciousPackages:
    """Verify new malicious package entries are flagged."""

    def test_new_malicious_packages_detected(self):
        """New malicious packages should be flagged."""
        for pkg in ["oura-ring-mcp-trojan", "supports-colors", "claude-code-helper"]:
            config = {"mcpServers": {"test": {"command": "npx", "args": [pkg]}}}
            findings = _scan_config(config)
            assert any(f["category"] == "known-malicious" for f in findings), f"Malicious package not detected: {pkg}"

    def test_smartloader_variant_detected(self):
        """SmartLoader variant should be flagged."""
        config = {"mcpServers": {"test": {"command": "npx", "args": ["@smartloader/oura-mcp"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "known-malicious" for f in findings)

    def test_openclaw_mcp_detected(self):
        """openclaw-mcp should be flagged."""
        config = {"mcpServers": {"test": {"command": "npx", "args": ["openclaw-mcp"]}}}
        findings = _scan_config(config)
        assert any(f["category"] == "known-malicious" for f in findings)

    def test_known_malicious_count(self):
        """Should have at least 7 malicious package entries."""
        assert len(config_guard.KNOWN_MALICIOUS) >= 7


# ═══════════════════════════════════════════════════════════════════
# NEW TESTS: SARIF Enhancements, CLI Flags, Pre-commit Hook
# ═══════════════════════════════════════════════════════════════════

import io
from contextlib import redirect_stdout


class TestSARIFEnhancements:
    """Tests for enhanced SARIF output: partialFingerprints, CWE tags, help.markdown."""

    def test_partial_fingerprints_present(self):
        """Each SARIF result should have partialFingerprints."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif = config_guard.format_sarif(findings, score)
        for result in sarif["runs"][0]["results"]:
            assert "partialFingerprints" in result
            assert "primaryLocationLineHash" in result["partialFingerprints"]
            # Must be a hex string (SHA-256)
            fp = result["partialFingerprints"]["primaryLocationLineHash"]
            assert len(fp) == 64
            assert all(c in "0123456789abcdef" for c in fp)

    def test_partial_fingerprints_deterministic(self):
        """Same finding should always produce the same fingerprint."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif1 = config_guard.format_sarif(findings, score, "test.json")
        sarif2 = config_guard.format_sarif(findings, score, "test.json")
        fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        assert fp1 == fp2

    def test_partial_fingerprints_differ_by_artifact(self):
        """Different artifact URIs should produce different fingerprints."""
        findings = [{"server": "test", "risk": "HIGH", "category": "shell-server",
                      "message": "test", "fix": "test"}]
        score = config_guard.calculate_score(findings)
        sarif1 = config_guard.format_sarif(findings, score, "file1.json")
        sarif2 = config_guard.format_sarif(findings, score, "file2.json")
        fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        assert fp1 != fp2

    def test_cwe_tags_in_rule_properties(self):
        """Rules should include CWE tags in properties."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif = config_guard.format_sarif(findings, score)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # shell-server rule should have CWE-78
        shell_rules = [r for r in rules if r["id"] == "mcp-shell-server"]
        assert len(shell_rules) == 1
        assert "tags" in shell_rules[0].get("properties", {})
        tags = shell_rules[0]["properties"]["tags"]
        assert any("CWE-78" in t for t in tags)

    def test_cwe_tags_in_result_properties(self):
        """Results should include CWE tags in properties."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif = config_guard.format_sarif(findings, score)
        results = sarif["runs"][0]["results"]
        # Find the shell-server result
        shell_results = [r for r in results if r["ruleId"] == "mcp-shell-server"]
        assert len(shell_results) >= 1
        assert "properties" in shell_results[0]
        assert "tags" in shell_results[0]["properties"]
        assert any("CWE-78" in t for t in shell_results[0]["properties"]["tags"])

    def test_help_markdown_in_rules(self):
        """Rules should include help.markdown remediation guidance."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif = config_guard.format_sarif(findings, score)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        shell_rules = [r for r in rules if r["id"] == "mcp-shell-server"]
        assert len(shell_rules) == 1
        assert "help" in shell_rules[0]
        assert "markdown" in shell_rules[0]["help"]
        assert "text" in shell_rules[0]["help"]
        assert "## Shell Command Server" in shell_rules[0]["help"]["markdown"]

    def test_help_text_strips_markdown(self):
        """help.text should be a plain-text version without markdown formatting."""
        config = {"mcpServers": {"risky": {"command": "bash", "args": []}}}
        findings = _scan_config(config)
        score = config_guard.calculate_score(findings)
        sarif = config_guard.format_sarif(findings, score)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        shell_rules = [r for r in rules if r["id"] == "mcp-shell-server"]
        help_text = shell_rules[0]["help"]["text"]
        # Should not contain markdown formatting characters
        assert "##" not in help_text
        assert "**" not in help_text

    def test_severity_mapping_critical_to_error(self):
        """CRITICAL findings should map to SARIF level 'error'."""
        findings = [{"server": "t", "risk": "CRITICAL", "category": "shell-server",
                      "message": "test", "fix": "test"}]
        sarif = config_guard.format_sarif(findings, 0)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_high_to_error(self):
        """HIGH findings should map to SARIF level 'error'."""
        findings = [{"server": "t", "risk": "HIGH", "category": "command-injection",
                      "message": "test", "fix": "test"}]
        sarif = config_guard.format_sarif(findings, 0)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_medium_to_warning(self):
        """MEDIUM findings should map to SARIF level 'warning'."""
        findings = [{"server": "t", "risk": "MEDIUM", "category": "rug-pull",
                      "message": "test", "fix": "test"}]
        sarif = config_guard.format_sarif(findings, 0)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_mapping_low_to_note(self):
        """LOW findings should map to SARIF level 'note'."""
        findings = [{"server": "t", "risk": "LOW", "category": "rug-pull",
                      "message": "test", "fix": "test"}]
        sarif = config_guard.format_sarif(findings, 0)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_severity_mapping_info_to_note(self):
        """INFO findings should map to SARIF level 'note'."""
        findings = [{"server": "t", "risk": "INFO", "category": "clean",
                      "message": "test", "fix": None}]
        sarif = config_guard.format_sarif(findings, 100)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_version_matches_package(self):
        """SARIF tool version should match package version."""
        sarif = config_guard.format_sarif([], 100)
        assert sarif["runs"][0]["tool"]["driver"]["version"] == config_guard.__version__

    def test_cwe_mapping_complete(self):
        """CWE_MAPPING should cover all non-clean/disabled categories in OWASP_MAPPING."""
        for category in config_guard.OWASP_MAPPING:
            if category in ("clean", "disabled"):
                continue
            assert category in config_guard.CWE_MAPPING, f"Missing CWE mapping for: {category}"

    def test_remediation_guidance_complete(self):
        """REMEDIATION_GUIDANCE should cover all non-clean/disabled categories."""
        for category in config_guard.OWASP_MAPPING:
            if category in ("clean", "disabled"):
                continue
            assert category in config_guard.REMEDIATION_GUIDANCE, f"Missing guidance for: {category}"


class TestCLISeverityThreshold:
    """Tests for --severity-threshold / -s flag."""

    def test_filter_by_severity_high(self):
        """--severity-threshold high should exclude MEDIUM/LOW/INFO."""
        findings = [
            {"server": "a", "risk": "CRITICAL", "category": "shell-server", "message": "x", "fix": "y"},
            {"server": "b", "risk": "HIGH", "category": "command-injection", "message": "x", "fix": "y"},
            {"server": "c", "risk": "MEDIUM", "category": "rug-pull", "message": "x", "fix": "y"},
            {"server": "d", "risk": "LOW", "category": "rug-pull", "message": "x", "fix": "y"},
            {"server": "e", "risk": "INFO", "category": "clean", "message": "x", "fix": None},
        ]
        filtered = config_guard._filter_by_severity(findings, "high")
        assert len(filtered) == 2
        assert all(f["risk"] in ("CRITICAL", "HIGH") for f in filtered)

    def test_filter_by_severity_medium(self):
        """--severity-threshold medium should exclude LOW/INFO."""
        findings = [
            {"server": "a", "risk": "CRITICAL", "category": "shell-server", "message": "x", "fix": "y"},
            {"server": "b", "risk": "MEDIUM", "category": "rug-pull", "message": "x", "fix": "y"},
            {"server": "c", "risk": "LOW", "category": "rug-pull", "message": "x", "fix": "y"},
            {"server": "d", "risk": "INFO", "category": "clean", "message": "x", "fix": None},
        ]
        filtered = config_guard._filter_by_severity(findings, "medium")
        assert len(filtered) == 2
        assert all(f["risk"] in ("CRITICAL", "MEDIUM") for f in filtered)

    def test_filter_by_severity_critical(self):
        """--severity-threshold critical should only keep CRITICAL."""
        findings = [
            {"server": "a", "risk": "CRITICAL", "category": "shell-server", "message": "x", "fix": "y"},
            {"server": "b", "risk": "HIGH", "category": "command-injection", "message": "x", "fix": "y"},
            {"server": "c", "risk": "MEDIUM", "category": "rug-pull", "message": "x", "fix": "y"},
        ]
        filtered = config_guard._filter_by_severity(findings, "critical")
        assert len(filtered) == 1
        assert filtered[0]["risk"] == "CRITICAL"

    def test_filter_by_severity_info_keeps_all(self):
        """--severity-threshold info should keep everything."""
        findings = [
            {"server": "a", "risk": "CRITICAL", "category": "shell-server", "message": "x", "fix": "y"},
            {"server": "b", "risk": "INFO", "category": "clean", "message": "x", "fix": None},
        ]
        filtered = config_guard._filter_by_severity(findings, "info")
        assert len(filtered) == 2

    def test_filter_by_severity_invalid_keeps_all(self):
        """Invalid threshold should keep all findings."""
        findings = [
            {"server": "a", "risk": "HIGH", "category": "command-injection", "message": "x", "fix": "y"},
        ]
        filtered = config_guard._filter_by_severity(findings, "invalid")
        assert len(filtered) == 1

    def test_cli_severity_threshold_integration(self):
        """CLI --severity-threshold should filter output findings."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "risky": {"command": "npx", "args": ["-y", "@some/pkg@latest"]},
            }}), encoding="utf-8")
            # Has MEDIUM (rug-pull @latest) and LOW (rug-pull -y) findings
            # With threshold=high, those should be filtered out
            sys.argv = ["config-guard", "--path", td, "-f", "json", "-s", "high"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            # Only HIGH or above should remain (known-vulnerable for mcp-related, unpinned, etc.)
            for f in output["findings"]:
                assert config_guard.RISK_LEVELS.get(f["risk"], 0) >= config_guard.RISK_LEVELS["HIGH"]


class TestCLIFormatFlag:
    """Tests for --format / -f flag."""

    def test_format_text(self):
        """--format text should produce human-readable output."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "text"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = buf.getvalue()
            assert "MCP Security Scan Results" in output
            assert "Security Score:" in output

    def test_format_json(self):
        """--format json should produce valid JSON output."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "json"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            assert "findings" in output
            assert "score" in output

    def test_format_sarif(self):
        """--format sarif should produce valid SARIF output."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "sarif"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            assert output["version"] == "2.1.0"
            assert "runs" in output

    def test_legacy_json_flag_still_works(self):
        """Legacy --json flag should still work."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--json"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            assert "findings" in output

    def test_legacy_sarif_flag_still_works(self):
        """Legacy --sarif flag should still work."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--sarif"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            assert output["version"] == "2.1.0"

    def test_format_flag_overrides_legacy(self):
        """--format should take precedence over --json/--sarif."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            # --format sarif should override --json
            sys.argv = ["config-guard", "--path", td, "--json", "-f", "sarif"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            output = json.loads(buf.getvalue())
            assert output["version"] == "2.1.0"  # SARIF format, not JSON


class TestCLIExitCode:
    """Tests for --exit-code flag."""

    def test_exit_code_0_clean(self):
        """--exit-code should return 0 for clean configs."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "json", "--exit-code"]
            try:
                config_guard.main()
                assert False, "Should have raised SystemExit"
            except SystemExit as e:
                assert e.code == 0

    def test_exit_code_1_medium_findings(self):
        """--exit-code should return 1 for medium findings (no critical/high)."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "risky": {"command": "npx", "args": ["@some/pkg@latest"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "json", "--exit-code", "-s", "medium"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                    assert False, "Should have raised SystemExit"
                except SystemExit as e:
                    # Should be 1 (findings present) since there are MEDIUM findings
                    assert e.code == 1

    def test_exit_code_2_critical_findings(self):
        """--exit-code should return 2 for critical/high findings."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "bad": {"command": "bash", "args": []}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "json", "--exit-code"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                    assert False, "Should have raised SystemExit"
                except SystemExit as e:
                    assert e.code == 2

    def test_legacy_exit_code_without_flag(self):
        """Without --exit-code, legacy behavior: 0=clean, 1=critical/high."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-f", "json"]
            try:
                config_guard.main()
                assert False, "Should have raised SystemExit"
            except SystemExit as e:
                assert e.code == 0

    def test_determine_exit_code_function(self):
        """Test _determine_exit_code directly."""
        clean = [{"server": "a", "risk": "INFO", "category": "clean", "message": "ok", "fix": None}]
        medium = [{"server": "a", "risk": "MEDIUM", "category": "rug-pull", "message": "x", "fix": "y"}]
        critical = [{"server": "a", "risk": "CRITICAL", "category": "shell-server", "message": "x", "fix": "y"}]

        # With exit_code=True
        assert config_guard._determine_exit_code(clean, True) == 0
        assert config_guard._determine_exit_code(medium, True) == 1
        assert config_guard._determine_exit_code(critical, True) == 2

        # Legacy (exit_code=False)
        assert config_guard._determine_exit_code(clean, False) == 0
        assert config_guard._determine_exit_code(medium, False) == 0  # medium not critical/high
        assert config_guard._determine_exit_code(critical, False) == 1


class TestCLIQuietFlag:
    """Tests for --quiet / -q flag."""

    def test_quiet_suppresses_output(self):
        """--quiet should produce no stdout output."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--quiet"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            assert buf.getvalue() == ""

    def test_quiet_with_findings_still_silent(self):
        """--quiet should suppress output even with findings."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "bad": {"command": "bash", "args": []}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-q"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                except SystemExit:
                    pass
            assert buf.getvalue() == ""

    def test_quiet_still_sets_exit_code(self):
        """--quiet should still set appropriate exit code."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "bad": {"command": "bash", "args": []}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "-q", "--exit-code"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    config_guard.main()
                    assert False, "Should have raised SystemExit"
                except SystemExit as e:
                    assert e.code == 2  # CRITICAL finding
            assert buf.getvalue() == ""


class TestCLIVersionFlag:
    """Tests for --version / -V flag."""

    def test_version_flag(self):
        """--version should print version and exit."""
        sys.argv = ["config-guard", "--version"]
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stderr(buf), redirect_stdout(buf):
            try:
                config_guard.main()
                assert False, "Should have raised SystemExit"
            except SystemExit as e:
                assert e.code == 0
        output = buf.getvalue()
        assert "2.0.0" in output


class TestPartialFingerprintFunction:
    """Tests for _partial_fingerprint helper."""

    def test_returns_sha256_hex(self):
        """Should return a 64-char hex string."""
        fp = config_guard._partial_fingerprint("mcp-shell-server", "test.json")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        """Same inputs should produce same output."""
        fp1 = config_guard._partial_fingerprint("mcp-a", "file.json")
        fp2 = config_guard._partial_fingerprint("mcp-a", "file.json")
        assert fp1 == fp2

    def test_different_inputs_differ(self):
        """Different inputs should produce different outputs."""
        fp1 = config_guard._partial_fingerprint("mcp-a", "file.json")
        fp2 = config_guard._partial_fingerprint("mcp-b", "file.json")
        assert fp1 != fp2


class TestCWEMapping:
    """Tests for CWE mapping data structure."""

    def test_cwe_mapping_is_dict(self):
        assert isinstance(config_guard.CWE_MAPPING, dict)

    def test_cwe_entries_have_id_and_name(self):
        """Each CWE entry should have 'id' and 'name' keys."""
        for category, cwes in config_guard.CWE_MAPPING.items():
            assert isinstance(cwes, list), f"{category}: CWE entries must be a list"
            for cwe in cwes:
                assert "id" in cwe, f"{category}: missing CWE 'id'"
                assert "name" in cwe, f"{category}: missing CWE 'name'"
                assert cwe["id"].startswith("CWE-"), f"{category}: CWE id must start with 'CWE-'"

    def test_known_cwe_mappings(self):
        """Verify specific CWE mappings are correct."""
        assert any(c["id"] == "CWE-78" for c in config_guard.CWE_MAPPING["command-injection"])
        assert any(c["id"] == "CWE-22" for c in config_guard.CWE_MAPPING["path-traversal"])
        assert any(c["id"] == "CWE-798" for c in config_guard.CWE_MAPPING["secret-leak"])
        assert any(c["id"] == "CWE-506" for c in config_guard.CWE_MAPPING["known-malicious"])
        assert any(c["id"] == "CWE-95" for c in config_guard.CWE_MAPPING["code-execution"])


class TestRemediationGuidance:
    """Tests for remediation guidance data structure."""

    def test_guidance_is_dict(self):
        assert isinstance(config_guard.REMEDIATION_GUIDANCE, dict)

    def test_guidance_entries_are_markdown(self):
        """Each guidance entry should contain markdown headers."""
        for category, guidance in config_guard.REMEDIATION_GUIDANCE.items():
            assert isinstance(guidance, str), f"{category}: guidance must be a string"
            assert "##" in guidance, f"{category}: guidance should contain markdown headers"
            assert "Remediation" in guidance, f"{category}: guidance should contain 'Remediation' section"

    def test_guidance_has_actionable_content(self):
        """Guidance should have at least some remediation content."""
        for category, guidance in config_guard.REMEDIATION_GUIDANCE.items():
            # Each guidance should have at least 50 chars of content
            assert len(guidance) >= 50, f"{category}: guidance too short"


class TestPreCommitHooksYAML:
    """Tests for .pre-commit-hooks.yaml file."""

    def test_pre_commit_hooks_exists(self):
        """Pre-commit hooks YAML file should exist."""
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        assert hooks_path.exists(), f"Missing .pre-commit-hooks.yaml at {hooks_path}"

    def test_pre_commit_hooks_valid_yaml(self):
        """Pre-commit hooks file should be valid YAML (parseable as list of dicts)."""
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        content = hooks_path.read_text(encoding="utf-8")
        # Basic YAML validation: should contain required fields
        assert "id:" in content
        assert "name:" in content
        assert "entry:" in content
        assert "language:" in content

    def test_pre_commit_hooks_entry_is_config_guard(self):
        """The hook entry point should be config-guard."""
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        content = hooks_path.read_text(encoding="utf-8")
        assert "entry: config-guard" in content

    def test_pre_commit_hooks_targets_json(self):
        """The hook should target JSON files."""
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        content = hooks_path.read_text(encoding="utf-8")
        assert "json" in content.lower()

    def test_pre_commit_hooks_uses_python_language(self):
        """The hook should use Python as the language."""
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        content = hooks_path.read_text(encoding="utf-8")
        assert "language: python" in content


class TestFilterBySeverityEdgeCases:
    """Edge cases for severity filtering."""

    def test_empty_findings(self):
        """Filtering empty list should return empty list."""
        assert config_guard._filter_by_severity([], "high") == []

    def test_low_threshold(self):
        """LOW threshold should include LOW, MEDIUM, HIGH, CRITICAL."""
        findings = [
            {"server": "a", "risk": "CRITICAL", "category": "x", "message": "x", "fix": "y"},
            {"server": "b", "risk": "HIGH", "category": "x", "message": "x", "fix": "y"},
            {"server": "c", "risk": "MEDIUM", "category": "x", "message": "x", "fix": "y"},
            {"server": "d", "risk": "LOW", "category": "x", "message": "x", "fix": "y"},
            {"server": "e", "risk": "INFO", "category": "x", "message": "x", "fix": None},
        ]
        filtered = config_guard._filter_by_severity(findings, "low")
        assert len(filtered) == 4
        assert not any(f["risk"] == "INFO" for f in filtered)

    def test_case_insensitive_threshold(self):
        """Threshold should be case-insensitive."""
        findings = [
            {"server": "a", "risk": "HIGH", "category": "x", "message": "x", "fix": "y"},
            {"server": "b", "risk": "LOW", "category": "x", "message": "x", "fix": "y"},
        ]
        filtered = config_guard._filter_by_severity(findings, "HIGH")
        assert len(filtered) == 1
        assert filtered[0]["risk"] == "HIGH"
