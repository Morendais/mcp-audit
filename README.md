# 🛡️ MCP-Hunter: Developer Security Scanner & DAST Fuzzer for MCP Servers

[![CI](https://github.com/mcp-hunter/mcp-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-hunter/mcp-hunter/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/mcp-hunter/mcp-hunter)](https://goreportcard.com/report/github.com/mcp-hunter/mcp-hunter)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **`mcp-hunter`** is a standalone, developer-first command-line security auditor and dynamic application security testing (DAST) fuzzer for the **Model Context Protocol (MCP)**. It identifies critical vulnerabilities—such as **Path Traversal, Remote Command Execution, SQL Injection, SSRF, Prompt Hijacking, and DoS type-confusion crashes**—before deploying MCP servers to production AI agents.

---

## 📊 The Global MCP Security Study (20,000+ Servers Audited)

`mcp-hunter` was born out of an extensive research project auditing the public MCP ecosystem (**20,010 servers analyzed** across npm, PyPI, and GitHub). 

### Key Findings:
```text
========================================================================
            GLOBAL MODEL CONTEXT PROTOCOL SECURITY LANDSCAPE            
========================================================================
• Total Analyzed Targets in Catalog : 20,010
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

## 🚀 Key Features

* **Zero-Setup Dynamic Fuzzing:** No configuration files required. Simply pass your server's startup command via `--exec`.
* **Deep Dynamic Verification:** Rather than static regex matching, `mcp-hunter` performs an MCP handshake (`initialize`), enumerates tools (`tools/list`), and executes targeted active payloads (`tools/call`) using safe canaries.
* **SARIF 2.1.0 Native:** Seamless integration with GitHub Code Scanning, GitLab SAST, and Microsoft Defender.
* **Claude Desktop & IDE Auto-Discovery:** Automatically inspects all configured MCP servers across Claude Desktop, Cursor, and Cline with a single command.
* **Non-Blocking Safety:** Strict timeouts, sandbox isolation, and process watchdog prevent hanging test runs.

---

## 📦 Installation

### Pre-built Binaries
Download the latest pre-compiled binary for Linux, macOS, or Windows from the [GitHub Releases](https://github.com/mcp-hunter/mcp-hunter/releases) page.

### Using Go
```bash
go install github.com/mcp-hunter/mcp-hunter@latest
```

### Build from Source
```bash
git clone https://github.com/mcp-hunter/mcp-hunter.git
cd mcp-hunter
go build -o mcp-hunter .
```

---

## 🛠️ Usage

### 1. Direct Execution Audit (`--exec`)
Audit any local MCP server executable directly without touching configuration files:

```bash
# Node.js MCP server
mcp-hunter scan --exec "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Python FastMCP server
mcp-hunter scan --exec "python3 ./weather_server.py"

# Compiled binary
mcp-hunter scan --exec "./my-mcp-binary --stdio"
```

### 2. Export SARIF for GitHub Code Scanning
Generate standard SARIF reports to display interactive vulnerability annotations on Pull Requests:

```bash
mcp-hunter scan --exec "node dist/index.js" --sarif results.sarif --fail-on critical
```

### 3. Audit Local Desktop Configuration
Automatically discover and audit all servers registered in Claude Desktop, Cursor, or Cline:

```bash
# Auto-detects Claude Desktop / Cursor config
mcp-hunter scan

# Audit a specific server from config
mcp-hunter scan --server memory-server

# Custom config file
mcp-hunter scan --config ~/.config/Claude/claude_desktop_config.json
```

### 4. Remote MCP Server Audit (SSE/HTTP)
Connect to an external or staging MCP server running over Server-Sent Events (SSE):

```bash
mcp-hunter remote http://localhost:8000/sse --format console
```

---

## 🛡️ Checks & Covered CWEs

| CWE | Vulnerability Class | Probe Mechanism |
|---|---|---|
| **CWE-22** | Path Traversal / Arbitrary File Read | Injects traversal sequences (`../../../../etc/passwd`, null-bytes, encoded variants) and inspects reflected file handles or parse errors. |
| **CWE-78** | OS Command Injection | Safely executes non-destructive canaries (`echo __MCP_SAFE_CANARY_<hash>__`) and validates process output reflection. |
| **CWE-89** | SQL Injection | Detects unescaped SQL syntax, sleep payloads, and database error reflection. |
| **CWE-918** | Server-Side Request Forgery (SSRF) | Detects internal loopback (`127.0.0.1`, `169.254.169.254`) requests and unvalidated URL parameters. |
| **CWE-20** | Type Confusion & Crash Bugs | Transmits oversized byte buffers and non-primitive JSON types to uncover unhandled exceptions that crash the MCP host. |
| **CWE-1021 / LLM01** | Prompt Hijacking | Evaluates tool description strings for hidden instruction overrides and system prompt injection vectors. |

---

## 🤖 CI/CD Integration (GitHub Actions)

Add this workflow to your `.github/workflows/mcp-audit.yml` to automatically verify every pull request:

```yaml
name: Security Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  mcp-hunter-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install mcp-hunter
        run: go install github.com/mcp-hunter/mcp-hunter@latest

      - name: Audit MCP Server
        run: |
          mcp-hunter scan \
            --exec "npm start" \
            --sarif mcp-report.sarif \
            --fail-on critical

      - name: Upload SARIF Report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-report.sarif
```

---

## 🏗️ Architecture & Ecosystem

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MCP-Hunter CLI Architecture                     │
├──────────────────────┬──────────────────────────┬──────────────────────┤
│    Input Sources     │     Engine & Fuzzer      │     Output Formats   │
│                      │                          │                      │
│ • --exec <cmd>       │ • JSON-RPC Handshake     │ • Colored Terminal   │
│ • Claude Desktop     │ • Schema Analyzer        │ • SARIF 2.1.0        │
│ • Cursor / Cline     │ • Active DAST Fuzzer     │ • JSON Reports       │
│ • Remote SSE Server  │ • Watchdog Sandbox       │ • Markdown Badges    │
└──────────────────────┴──────────────────────────┴──────────────────────┘
```

> **Enterprise Threat Intelligence Note:**  
> The distributed cloud telemetry collector, autonomous registry crawler, and mobile monitoring dashboard used in the 20,000-server study operate on private enterprise infrastructure and are separate from this open-source CLI engine.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
