# 🛡️ MCP-Audit: Developer Security Scanner & DAST Fuzzer for MCP Servers

[![CI](https://github.com/mcp-audit/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-audit/mcp-audit/actions)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![npm version](https://img.shields.io/npm/v/mcp-audit.svg)](https://www.npmjs.com/package/mcp-audit)

> **`mcp-audit`** is a zero-config, developer-first command-line security auditor and dynamic application security testing (DAST) fuzzer for the **Model Context Protocol (MCP)**. It identifies critical vulnerabilities—such as **Path Traversal, Remote Command Execution, SQL Injection, SSRF, Prompt Hijacking, and DoS type-confusion crashes**—before deploying MCP servers to production AI agents.

---

## ⚡ Quick Start: 0-Second Run

### Option A: Run instantly via `npx` (No installation needed)
```bash
npx mcp-audit
```

### Option B: Native Shell Install
**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/<your-username>/mcp-audit/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/<your-username>/mcp-audit/main/install.ps1 | iex
```

### Option C: Go Install / Binaries
```bash
go install github.com/mcp-audit/mcp-audit@latest
```

---

## 🎮 Zero-Config Interactive TUI (Default Mode)

When executed without arguments, `mcp-audit` **never dumps useless help text**. Instead, it automatically discovers MCP environments across **Claude Desktop, Cursor, and Windsurf**, detects all registered servers, and opens an interactive express audit wizard:

```text
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                     mcp-audit — Zero-Config Security Auditor                     ║
╚═══════════════════════════════════════════════════════════════════════════════════╝

Discovered 3 MCP servers in Claude Desktop:
 > [x] filesystem-server (npx -y @modelcontextprotocol/server-filesystem /tmp)
   [x] sqlite-query      (python -m mcp_server_sqlite --db test.db)
   [ ] custom-dev-api    (node ./dist/index.js)

Controls: [↑/↓] Navigate  [Space] Toggle  [a] Toggle All  [Enter] Start Audit  [q] Quit
```

### 🚦 Traffic Light Scorecard

Instead of overwhelming walls of raw logs, `mcp-audit` displays a clean, immediate traffic-light verdict:

```text
══════════════════════════════════════════════════════════════════════════════
                       MCP SECURITY SCORECARD
══════════════════════════════════════════════════════════════════════════════

🟢 filesystem-server: Secure (CWE-22 defended, 4 tools tested)

🔴 sqlite-query: Uncontrolled filesystem access detected (CRITICAL)
   └─ Confirmed exploit: Arbitrary File Read (Path Traversal) in tool "query_file"

🟡 custom-dev-api: Unhandled crash bug on invalid input (CWE-20 DoS)
   └─ Process crashed via Type Confusion in tool "process_record"

──────────────────────────────────────────────────────────────────────────────
SUMMARY: Total: 3 | Secure: 1 | Critical: 1 | Warning: 1 | Blocked: 0
Tip: Run with --verbose for full JSON-RPC traces or --sarif report.sarif for CI/CD.
══════════════════════════════════════════════════════════════════════════════
```

---

## 🛠️ CLI Power Usage

### 1. Direct Execution Audit (`--exec`)
Audit any local MCP server executable directly without touching configuration files:

```bash
# Node.js MCP server
mcp-audit scan --exec "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Python FastMCP server
mcp-audit scan --exec "python3 ./weather_server.py"

# Compiled binary
mcp-audit scan --exec "./my-mcp-binary --stdio"
```

### 2. Export SARIF for GitHub Code Scanning & CI/CD
Generate standard SARIF reports to display interactive vulnerability annotations on Pull Requests:

```bash
mcp-audit scan --exec "node dist/index.js" --sarif results.sarif --fail-on critical
```

### 3. Audit Remote HTTP / SSE MCP Endpoints
```bash
mcp-audit remote --sse http://localhost:8080/sse
```

---

## 📊 The Global MCP Security Study (20,010 Servers Audited)

`mcp-audit` was born out of an extensive research project auditing the public MCP ecosystem (**20,010 servers analyzed** across npm, PyPI, and GitHub). 

### Key Study Statistics:
```text
========================================================================
            GLOBAL MODEL CONTEXT PROTOCOL SECURITY LANDSCAPE            
========================================================================
• Total Analyzed Targets in Catalog : 20,010 (100% complete)
• Ready "Out-of-the-box" Servers    :  7,375 (36.8%)
• Hard External Auth / Token Walls :  7,804 (39.0%)
• Require Manual CLI Options/Flags  :  3,030 (15.1%)
• Broken Dependencies / Build Errors:  1,647 ( 8.2%)

CRITICAL SECURITY TELEMETRY (From 7,375 Live Fuzzed Servers):
------------------------------------------------------------------------
• Total Telemetry Events Recorded   : 41,224
• Confirmed Exploit-Verified Flaws  :    290 (CRITICAL / HIGH)
• Type Confusion Crash Bugs (DoS)   :    752 (CWE-20)
• Defended & Filtered Vector Probes : 14,884 (DEFENDED)
• Unrestricted Attack Surface Points: 24,891 (POTENTIAL EXPOSURE)

TOP VULNERABILITY CLASSES IDENTIFIED:
 1. CWE-22   Path Traversal (Arbitrary File Read/Write)   : 16,199 vectors
 2. CWE-250  Execution with Unnecessary Privileges        :  8,195 vectors
 3. CWE-918  Server-Side Request Forgery (SSRF)          :  7,674 vectors
 4. CWE-89   SQL Injection via Unsanitized Parameters    :  5,223 vectors
 5. CWE-78   OS Command Injection (Remote Code Execution) :  2,928 vectors
 6. CWE-20   Unhandled Input Panic / Denial of Service    :    989 vectors
 7. CWE-1021 Prompt Hijacking / System Instruction Override:   16 servers
========================================================================
```

> **Takeaway:** Over **39%** of public MCP packages cannot start without proprietary SaaS credentials, and among the self-contained servers that *do* execute, **over 40%** expose parameters susceptible to Path Traversal or Arbitrary Command Execution when driven by autonomous LLM agents.

---

## 🤖 GitHub Action Integration

Add continuous MCP security scanning to `.github/workflows/mcp-security.yml`:

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
          npx mcp-audit scan --exec "node dist/index.js" --sarif results.sarif --fail-on critical

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
