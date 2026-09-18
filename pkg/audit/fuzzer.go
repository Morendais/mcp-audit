package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"mcp-audit/pkg/protocol"
)

// FuzzTool executes dynamic active verification probes against a suspected tool attack surface.
func FuzzTool(ctx context.Context, caller protocol.ToolCaller, tool protocol.Tool, finding Finding) Finding {
	fuzzedFinding := finding

	// Short timeout for individual probe to avoid stalling the scan
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	var result Finding
	switch finding.Category {
	case CategoryPathTraversal:
		result = fuzzPathTraversal(probeCtx, caller, tool, fuzzedFinding)

	case CategoryRCE:
		result = fuzzRCE(probeCtx, caller, tool, fuzzedFinding)

	default:
		result = fuzzedFinding
	}

	// Active Type Confusion & Boundary Crash Probes (CWE-20)
	// If the tool has not already been confirmed vulnerable, test if invalid types or oversized inputs crash the server
	if result.Status != StatusConfirmed {
		if crashFinding := fuzzTypeConfusion(probeCtx, caller, tool, result); crashFinding != nil {
			return *crashFinding
		}
	}

	return result
}

func fuzzPathTraversal(ctx context.Context, caller protocol.ToolCaller, tool protocol.Tool, f Finding) Finding {
	targetParam := f.ParameterName
	paramPath := f.ParameterPath
	if paramPath == "" {
		paramPath = targetParam
	}

	// Comprehensive mutation payloads for path traversal (raw, url-encoded, double url-encoded, null-byte, windows)
	payloads := []string{
		"../../../../../../../../etc/passwd",
		"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
		"../../../../../../../../etc/passwd%00.json",
		"/etc/passwd",
		`..\..\..\..\..\..\..\..\Windows\win.ini`,
		`..%5c..%5c..%5c..%5cWindows\win.ini`,
	}

	defendedOnce := false
	var lastDefenseMsg string

	for _, payload := range payloads {
		args := buildArgumentsForPath(tool, paramPath, payload)
		f.FuzzPayload = payload

		res, err := caller.CallTool(ctx, tool.Name, args)
		if err != nil {
			errStr := err.Error()
			f.FuzzResponse = errStr

			// Check for stateful prerequisites (unauthorized, session missing, unconfigured DB)
			if isPrerequisiteFailure(errStr) {
				f.Status = StatusPrerequisiteFailed
				f.Severity = SeverityLow
				f.Title = fmt.Sprintf("PREREQUISITE FAILED: Tool '%s' requires session or credentials", tool.Name)
				f.Description = fmt.Sprintf("Dynamic probe could not be performed because the tool requires prior configuration: %s", errStr)
				return f
			}

			if strings.Contains(strings.ToLower(errStr), "closed") || strings.Contains(strings.ToLower(errStr), "eof") || strings.Contains(strings.ToLower(errStr), "broken pipe") {
				f.Status = StatusCrashed
				f.Severity = SeverityHigh
				f.Title = fmt.Sprintf("CRASH BUG: Server terminated on Path Traversal payload in '%s'", tool.Name)
				f.Description = fmt.Sprintf("The server crashed with an unhandled exception when provided with payload '%s'.", payload)
				return f
			}

			// Server returned an error, indicating potential defense for this specific payload.
			// Continue to next mutation in case a different encoding bypasses the filter!
			defendedOnce = true
			lastDefenseMsg = errStr
			continue
		}

		responseText := extractResultText(res)
		f.FuzzResponse = truncateString(responseText, 200)

		if isPrerequisiteFailure(responseText) {
			f.Status = StatusPrerequisiteFailed
			f.Severity = SeverityLow
			f.Title = fmt.Sprintf("PREREQUISITE FAILED: Tool '%s' requires session or credentials", tool.Name)
			f.Description = fmt.Sprintf("Tool returned prerequisite error: %s", truncateString(responseText, 120))
			return f
		}

		// Check for /etc/passwd contents (root:x: or root:*: or daemon: or nobody:)
		if strings.Contains(responseText, "root:") || strings.Contains(responseText, "daemon:") || strings.Contains(responseText, "nobody:") {
			f.Status = StatusConfirmed
			f.Severity = SeverityCritical
			f.Title = fmt.Sprintf("CONFIRMED VULNERABILITY: Arbitrary File Read (Path Traversal) in '%s'", tool.Name)
			f.Description = fmt.Sprintf("Dynamic verification SUCCEEDED. The server returned host system file contents (/etc/passwd) using payload '%s' for parameter '%s'.", payload, paramPath)
			f.Evidence = fmt.Sprintf("Payload: %s -> Response contained: %s", payload, truncateString(responseText, 120))
			f.Recommendation = "CRITICAL: Immediately implement strict file path validation using filepath.Clean and verify paths stay within the designated workspace root."
			return f
		}

		// Check for win.ini contents
		if strings.Contains(strings.ToLower(responseText), "[fonts]") || strings.Contains(strings.ToLower(responseText), "[extensions]") {
			f.Status = StatusConfirmed
			f.Severity = SeverityCritical
			f.Title = fmt.Sprintf("CONFIRMED VULNERABILITY: Arbitrary File Read (Path Traversal) in '%s'", tool.Name)
			f.Description = fmt.Sprintf("Dynamic verification SUCCEEDED. The server returned host system file contents (win.ini) using payload '%s' for parameter '%s'.", payload, paramPath)
			f.Evidence = fmt.Sprintf("Payload: %s -> Response contained: %s", payload, truncateString(responseText, 120))
			f.Recommendation = "CRITICAL: Immediately implement strict file path validation using filepath.Clean and verify paths stay within the designated workspace root."
			return f
		}

		if res.IsError || containsDefenseWords(responseText) {
			defendedOnce = true
			lastDefenseMsg = responseText
			continue
		}
	}

	if defendedOnce {
		f.Status = StatusDefended
		f.Severity = SeverityInfo
		f.Title = fmt.Sprintf("DEFENDED: Tool '%s' sanitized or rejected Path Traversal mutation probes", tool.Name)
		f.Description = fmt.Sprintf("Server consistently rejected path traversal mutations: %s", truncateString(lastDefenseMsg, 120))
		return f
	}

	return f
}

func fuzzRCE(ctx context.Context, caller protocol.ToolCaller, tool protocol.Tool, f Finding) Finding {
	targetParam := f.ParameterName
	paramPath := f.ParameterPath
	if paramPath == "" {
		paramPath = targetParam
	}

	// Safe Non-Destructive Canary: random nonce echo
	nonce := generateSafeCanary()
	payload := fmt.Sprintf("echo %s", nonce)

	args := buildArgumentsForPath(tool, paramPath, payload)
	f.FuzzPayload = payload

	res, err := caller.CallTool(ctx, tool.Name, args)
	if err != nil {
		errStr := err.Error()
		f.FuzzResponse = errStr

		if isPrerequisiteFailure(errStr) {
			f.Status = StatusPrerequisiteFailed
			f.Severity = SeverityLow
			f.Title = fmt.Sprintf("PREREQUISITE FAILED: Tool '%s' requires session or credentials", tool.Name)
			f.Description = fmt.Sprintf("Tool returned prerequisite error: %s", errStr)
			return f
		}

		if strings.Contains(strings.ToLower(errStr), "closed") || strings.Contains(strings.ToLower(errStr), "eof") {
			f.Status = StatusCrashed
			f.Severity = SeverityHigh
			f.Title = fmt.Sprintf("CRASH BUG: Server process died on RCE payload in '%s'", tool.Name)
			return f
		}
		f.Status = StatusDefended
		f.Severity = SeverityInfo
		f.Title = fmt.Sprintf("DEFENDED: Tool '%s' rejected command execution probe", tool.Name)
		return f
	}

	responseText := extractResultText(res)
	f.FuzzResponse = truncateString(responseText, 200)

	if isPrerequisiteFailure(responseText) {
		f.Status = StatusPrerequisiteFailed
		f.Severity = SeverityLow
		f.Title = fmt.Sprintf("PREREQUISITE FAILED: Tool '%s' requires session or credentials", tool.Name)
		return f
	}

	// High-confidence RCE verification:
	// Real shell execution of "echo <nonce>" outputs <nonce>, NOT "echo <nonce>".
	// If the response contains the entire command "echo <nonce>" or schema/syntax errors,
	// it was an input reflection or error reject, NOT a shell execution!
	hasNonce := strings.Contains(responseText, nonce)
	isEchoReflection := strings.Contains(responseText, payload)
	isExecutionError := res.IsError || isReflectedError(responseText)

	if hasNonce && !isEchoReflection && !isExecutionError {
		f.Status = StatusConfirmed
		f.Severity = SeverityCritical
		f.Title = fmt.Sprintf("CONFIRMED VULNERABILITY: Remote Code Execution (RCE) in '%s'", tool.Name)
		f.Description = fmt.Sprintf("Dynamic verification SUCCEEDED. The server executed the safe canary command and returned unique execution marker '%s'.", nonce)
		f.Evidence = fmt.Sprintf("Payload: %s -> Response: %s", payload, truncateString(responseText, 120))
		f.Recommendation = "CRITICAL: Do not pass untrusted parameter strings into shell or exec functions. Replace raw execution with whitelisted structured arguments or container sandboxes."
		return f
	}

	if res.IsError || containsDefenseWords(responseText) || isEchoReflection || isExecutionError {
		f.Status = StatusDefended
		f.Severity = SeverityInfo
		f.Title = fmt.Sprintf("DEFENDED: Tool '%s' rejected command execution probe", tool.Name)
		return f
	}

	return f
}

func fuzzTypeConfusion(ctx context.Context, caller protocol.ToolCaller, tool protocol.Tool, f Finding) *Finding {
	paramPath := f.ParameterPath
	if paramPath == "" {
		paramPath = f.ParameterName
	}
	if paramPath == "" {
		return nil
	}

	// 1. null probe
	// 2. empty array probe []
	// 3. 65KB oversized buffer probe
	typeProbes := []struct {
		name    string
		payload any
	}{
		{"null_type", nil},
		{"empty_array", []any{}},
		{"oversized_65k_buffer", strings.Repeat("A", 65536)},
	}

	for _, probe := range typeProbes {
		args := buildArgumentsForPath(tool, paramPath, probe.payload)
		_, err := caller.CallTool(ctx, tool.Name, args)
		if err != nil {
			errStr := err.Error()
			lower := strings.ToLower(errStr)
			// Check if the server process crashed or panicked
			if strings.Contains(lower, "closed") || strings.Contains(lower, "eof") ||
				strings.Contains(lower, "broken pipe") || strings.Contains(lower, "connection reset") ||
				strings.Contains(errStr, "panic:") || strings.Contains(errStr, "Traceback") {
				crashFinding := f
				crashFinding.Status = StatusCrashed
				crashFinding.Severity = SeverityHigh
				crashFinding.Category = CategoryCrashBug
				crashFinding.CWEID = "CWE-20"
				crashFinding.CWETitle = "Improper Input Validation / Type Confusion Crash"
				crashFinding.Title = fmt.Sprintf("CRASH BUG: Server crashed on %s payload in '%s'", probe.name, tool.Name)
				crashFinding.Description = fmt.Sprintf("Dynamic probe revealed unhandled runtime panic/crash when parameter '%s' was sent a %s payload: %s", paramPath, probe.name, truncateString(errStr, 150))
				crashFinding.Evidence = fmt.Sprintf("Payload: %s -> Server died with: %s", probe.name, truncateString(errStr, 150))
				crashFinding.Recommendation = "Enforce strict schema validation and error recovery to prevent unhandled runtime panics and denial of service."
				return &crashFinding
			}
		}
	}
	return nil
}

func generateSafeCanary() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "__MCP_CANARY_SAFE_PROBE__"
	}
	return fmt.Sprintf("__MCP_SAFE_CANARY_%s__", hex.EncodeToString(b))
}

func isPrerequisiteFailure(s string) bool {
	lower := strings.ToLower(s)
	markers := []string{
		"unauthorized",
		"api key required",
		"api key missing",
		"authentication failed",
		"not configured",
		"no credentials",
		"session not found",
		"connection closed",
		"database not open",
		"no database selected",
		"please authenticate",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// buildArgumentsForPath constructs a nested argument map supporting dot-separated paths (e.g. "options.file.path").
func buildArgumentsForPath(tool protocol.Tool, paramPath string, payload any) map[string]any {
	root := make(map[string]any)

	// Populate dummy values for all required parameters at root level
	for _, req := range tool.InputSchema.Required {
		propDef := tool.InputSchema.Properties[req]
		switch propDef.TypeString() {
		case "integer", "number":
			root[req] = 1
		case "boolean":
			root[req] = true
		default:
			root[req] = "test"
		}
	}

	// Now set the payload at paramPath
	parts := strings.Split(paramPath, ".")
	if len(parts) == 1 {
		root[parts[0]] = payload
		return root
	}

	// Traverse/build nested map
	current := root
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]
		existing, ok := current[key]
		if !ok {
			subMap := make(map[string]any)
			current[key] = subMap
			current = subMap
		} else if subMap, ok := existing.(map[string]any); ok {
			current = subMap
		} else {
			subMap := make(map[string]any)
			current[key] = subMap
			current = subMap
		}
	}

	current[parts[len(parts)-1]] = payload
	return root
}

func extractResultText(res *protocol.CallToolResult) string {
	if res == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range res.Content {
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}
	return sb.String()
}

func containsDefenseWords(s string) bool {
	lower := strings.ToLower(s)
	words := []string{
		"permission denied",
		"access denied",
		"forbidden",
		"outside sandbox",
		"outside root",
		"outside_root",
		"outside allowed",
		"outside workspace",
		"escapes workspace",
		"escape workspace",
		"path escapes",
		"invalid path",
		"invalid_input",
		"not allowed",
		"disallowed",
		"not permitted",
		"path traversal",
		"confined",
		"must be within",
		"not within allowed",
		"safety restriction",
		"directory traversal",
		"containment check",
		"choke point",
		"illegal path",
	}
	for _, w := range words {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func isReflectedError(s string) bool {
	lower := strings.ToLower(s)
	markers := []string{
		"invalid",
		"expected",
		"unexpected token",
		"syntax error",
		"parse error",
		"erro:",
		"error:",
		"allowlist",
		"whitelist",
		"not in the",
		"unknown command",
		"unrecognized",
		"no diagram type",
		"unknown node",
		"repaired node",
		"validation",
		"zoderror",
		"typeerror",
		"bad argument",
		"illegal",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
