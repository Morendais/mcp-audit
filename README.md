# mcpaudit

Developer Security Scanner and Dynamic Application Security Testing (DAST) Fuzzer for Model Context Protocol (MCP) Servers.

[![CI](https://github.com/Morendais/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Morendais/mcp-audit/actions)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![npm version](https://img.shields.io/npm/v/@morendais/mcpaudit.svg)](https://www.npmjs.com/package/@morendais/mcpaudit)

> **Important Notice & Disclaimer:**
> `mcpaudit` is created strictly for developers, system administrators, and security researchers to audit and verify **their own** Model Context Protocol (MCP) servers or environments where they have explicit, written permission to test.
> The author and contributors disclaim any and all liability for misuse, abuse, unauthorized testing, or damages resulting from the use of this software. You are solely responsible for ensuring your testing activities comply with all applicable local, national, and international laws.

---

## Overview

`mcpaudit` is a standalone, zero-config command-line security auditor designed specifically for the Model Context Protocol ecosystem. 

Rather than relying purely on static regex matching, `mcpaudit` initiates an actual JSON-RPC 2.0 handshake over stdio or SSE, discovers registered tools and their JSON schemas, and conducts non-destructive dynamic fuzzing to identify critical vulnerabilities before servers are connected to autonomous LLM agents (Claude Desktop, Cursor, Windsurf):

- **Path Traversal (CWE-22):** Unauthorized access to arbitrary files outside sandbox boundaries.
- **OS Command Injection (CWE-78):** Unescaped shell argument execution.
- **Server-Side Request Forgery (SSRF / CWE-918):** Unrestricted access to cloud metadata endpoints or internal network services.
- **SQL Injection (CWE-89):** Raw, unparameterized query execution.
- **Type Confusion & Denial of Service (CWE-20 DoS):** Process crashes caused by unhandled types, missing properties, or invalid JSON-RPC payloads.

---

## Quick Start

### Option 1: Run instantly via npx (Zero-install)
```bash
npx @morendais/mcpaudit
```

### Option 2: Pre-built Binaries (GitHub Releases)
Download standalone executable archives from [GitHub Releases](https://github.com/Morendais/mcp-audit/releases/latest):
- **Windows:** Download `mcpaudit_windows_amd64.zip`, extract and run `mcpaudit.exe`.
- **Linux:** Download `mcpaudit_linux_amd64.tar.gz`.
- **macOS:** Download `mcpaudit_darwin_arm64.tar.gz` (Apple Silicon) or `mcpaudit_darwin_amd64.tar.gz` (Intel).

### Option 3: Go Install
```bash
go install github.com/Morendais/mcp-audit@latest
```

---

## Zero-Config Interactive TUI

When executed without arguments, `mcpaudit` skips generic help banners. It automatically inspects default configuration paths across **Claude Desktop, Cursor, and Windsurf** as well as local workspace configs, presenting an interactive express audit menu:

```text
+-----------------------------------------------------------------------------+
|                     mcpaudit -- Zero-Config Security Auditor                |
+-----------------------------------------------------------------------------+

Discovered 3 MCP servers in Claude Desktop:
 > [x] filesystem-server (npx -y @modelcontextprotocol/server-filesystem /tmp)
   [x] sqlite-query      (python -m mcp_server_sqlite --db test.db)
   [ ] custom-dev-api    (node ./dist/index.js)

Controls: [Up/Down] Navigate  [Space] Toggle  [a] Toggle All  [Enter] Start Audit  [q] Quit
```

### Traffic Light Scorecard

Instead of unreadable walls of raw debug logs, `mcpaudit` summarizes the security posture of every server into an immediate visual card:

```text
==============================================================================
                            MCP SECURITY SCORECARD
==============================================================================

[SECURE]   filesystem-server: Defended (CWE-22 defended, 4 tools tested)

[CRITICAL] sqlite-query: Uncontrolled filesystem access detected (CRITICAL)
           └─ Confirmed exploit: Arbitrary File Read (Path Traversal) in tool "query_file"

[WARNING]  custom-dev-api: Unhandled crash bug on invalid input (CWE-20 DoS)
           └─ Process crashed via Type Confusion in tool "process_record"

------------------------------------------------------------------------------
SUMMARY: Total: 3 | Secure: 1 | Critical: 1 | Warning: 1 | Blocked: 0
Tip: Run with --verbose for full JSON-RPC traces or --sarif report.sarif for CI/CD.
==============================================================================
```

---

## Limitations and Manual Verification

Automated dynamic testing and heuristic schema analysis provide fast, high-coverage feedback, but **automated tools can make mistakes**. Automated findings must always be reviewed in context by a human engineer.

### False Positives (Examples)
1. **Simulated / Mock Tools:** A server written for demonstration or testing that returns static fixture text containing string fragments like `/etc/passwd` or dummy host configurations will trigger a Path Traversal alert, even though it never accesses real disk files.
2. **Legitimate Administrative / Terminal Tools:** A server intentionally built to give an LLM command-line or bash access (e.g., a local coding assistant running build scripts) will naturally flag CWE-78 (Command Execution) and CWE-250 (Excessive Privileges). When intended for single-user sandboxed environments, this is designed functionality rather than a bug.
3. **Non-Standard Error Envelopes:** If a server encounters an invalid type and exits cleanly with a custom status code rather than returning a structured JSON-RPC error response, the tool may classify the process termination as an unhandled crash bug (CWE-20).

### False Negatives (Examples)
1. **Authentication Walls:** If a server requires external API credentials (e.g. Stripe, AWS, GitHub tokens) and fails during the initial handshake, its internal tools cannot be enumerated or fuzzed without credentials.
2. **Complex Semantic Requirements:** Tools that only trigger vulnerable codepaths when given interdependent arguments (e.g. a specific valid session ID combined with a manipulated path) will not be exploited by single-parameter mutation passes.

Always perform secondary manual verification before filing bug reports or pushing code to production.

---

## CLI Usage

### Direct Command Audit (--exec)
Audit any local MCP server executable directly without configuration files:

```bash
# Node.js MCP server
mcpaudit scan --exec "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Python FastMCP server
mcpaudit scan --exec "python3 ./weather_server.py"

# Compiled binary
mcpaudit scan --exec "./my-mcp-binary --stdio"
```

### SARIF 2.1.0 Export for CI/CD
Generate standard SARIF reports for GitHub Code Scanning, GitLab SAST, or IDE viewers:

```bash
mcpaudit scan --exec "node dist/index.js" --sarif results.sarif --fail-on critical
```

### Remote Server Audit (--sse)
Audit remote HTTP/SSE Model Context Protocol endpoints:

```bash
mcpaudit remote --sse http://localhost:8080/sse
```

---

## CI/CD Integration (GitHub Actions)

Add continuous MCP security scanning to your repository under `.github/workflows/mcp-security.yml`:

```yaml
name: MCP Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run MCP Audit
        run: |
          npx @morendais/mcpaudit scan --exec "node dist/index.js" --sarif results.sarif --fail-on critical

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
