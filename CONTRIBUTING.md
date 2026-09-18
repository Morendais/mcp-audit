# Contributing to MCP-Audit

Thank you for your interest in improving `mcp-audit`!

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Morendais/mcp-audit.git
   cd mcp-audit
   ```

2. **Run tests:**
   ```bash
   go test -v ./...
   ```

3. **Build local binary:**
   ```bash
   go build -o mcp-audit .
   ```

4. **Verify zero-config scan:**
   ```bash
   ./mcp-audit
   ```

## Pull Request Guidelines
- Ensure all tests pass (`go test ./...`).
- Keep code formatted with `go fmt ./...`.
- Add test coverage for any newly introduced features or fuzzer rules.
- Follow responsible disclosure for any newly discovered vulnerabilities.
