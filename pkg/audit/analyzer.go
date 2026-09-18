package audit

import (
	"fmt"
	"regexp"
	"strings"

	"mcp-audit/pkg/config"
	"mcp-audit/pkg/protocol"
)

var (
	secretKeyRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|auth[_-]?token|private[_-]?key|database_url)`)
	secretValRegex = regexp.MustCompile(`(?i)^(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{20,}|xoxb-[a-zA-Z0-9-]{20,}|postgres://|mysql://|mongodb://)`)

	rceParamRegex   = regexp.MustCompile(`(?i)^(cmd|command|script|code|bash|sh|shell|exec|eval|run)$`)
	fileParamRegex  = regexp.MustCompile(`(?i)(path|filepath|file_path|dir|directory|folder|filename)$`)
	ssrfParamRegex  = regexp.MustCompile(`(?i)(url|uri|endpoint|webhook|target_url|callback_url)$`)
	sqliParamRegex  = regexp.MustCompile(`(?i)(query|sql|statement|sql_query)$`)
	dangerWordRegex = regexp.MustCompile(`(?i)\b(delete|drop|kill|destroy|truncate|erase|format|reboot|shutdown|wipe|rm)\b`)

	promptInjectionRegex = regexp.MustCompile(`(?i)(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s+override|you\s+are\s+now\s+(in\s+)?developer\s+mode|disregard\s+(all\s+)?prior|bypass\s+safety\s+filter|reveal\s+(system\s+)?prompt|print\s+(system\s+)?prompt|new\s+system\s+instruction)`)
	hiddenUnicodeRegex   = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{202E}\x{2060}]`)

	containmentHintsRegex = regexp.MustCompile(`(?i)(resolveinroot|safepath|assertconfined|sandbox|scoped to|workspace root|relative to|inside workspace)`)
	tempFilespaceRegex    = regexp.MustCompile(`(?i)(authored|tmpdir|temporary directory|temp file|build artifact|generated plan|cache)`)
)

// AnalyzeServerConfig checks server launch configuration for credential leaks or insecure configurations.
func AnalyzeServerConfig(serverName string, srv config.ServerConfig) []Finding {
	var findings []Finding

	for key, val := range srv.Env {
		if secretKeyRegex.MatchString(key) || secretValRegex.MatchString(val) {
			maskedVal := maskSecret(val)
			findings = append(findings, Finding{
				Status:        StatusConfirmed,
				Severity:      SeverityHigh,
				Category:      CategorySecretLeak,
				CWEID:         "CWE-798",
				CWETitle:      "Use of Hard-coded Credentials",
				ServerName:    serverName,
				ParameterName: key,
				Title:         fmt.Sprintf("Hardcoded secret in server environment variable '%s'", key),
				Description:   fmt.Sprintf("Environment variable '%s' contains sensitive credentials in plaintext in the client configuration file.", key),
				Evidence:      fmt.Sprintf("%s=%s", key, maskedVal),
				Recommendation: "Avoid storing plaintext API keys and credentials in configuration files. Use environment variable expansion or a secure secret manager.",
			})
		}
	}

	return findings
}

// AnalyzeTool performs static attack surface analysis on an MCP tool's metadata and argument schema.
func AnalyzeTool(serverName string, tool protocol.Tool) []Finding {
	var findings []Finding

	toolNameLower := strings.ToLower(tool.Name)
	descLower := strings.ToLower(tool.Description)

	// 1. Check for Excessive Agency / Destructive Tool actions
	if dangerWordRegex.MatchString(toolNameLower) || dangerWordRegex.MatchString(descLower) {
		findings = append(findings, Finding{
			Status:         StatusAttackSurface,
			Severity:       SeverityMedium,
			Category:       CategoryExcessiveAgency,
			CWEID:          "CWE-250",
			CWETitle:       "Execution with Unnecessary Privileges",
			ServerName:     serverName,
			ToolName:       tool.Name,
			Title:          fmt.Sprintf("Attack Surface: Tool '%s' performs potentially destructive operations", tool.Name),
			Description:    "The tool name or description indicates destructive capabilities (e.g., delete, drop, wipe, kill). If invoked by an LLM without human confirmation, it could cause data loss or system disruption.",
			Evidence:       fmt.Sprintf("Tool name: %s, Description: %s", tool.Name, tool.Description),
			Recommendation: "Implement confirmation safeguards (Human-in-the-Loop) and restrict permissions to readonly or staging environments where possible.",
		})
	}

	// 2. Check for RCE / Arbitrary Command Execution tools
	if regexp.MustCompile(`(?i)(exec|execute_command|run_command|shell|bash|eval)`).MatchString(toolNameLower) {
		findings = append(findings, Finding{
			Status:         StatusAttackSurface,
			Severity:       SeverityHigh,
			Category:       CategoryRCE,
			CWEID:          "CWE-78",
			CWETitle:       "OS Command Injection",
			ServerName:     serverName,
			ToolName:       tool.Name,
			Title:          fmt.Sprintf("Attack Surface: Tool '%s' exposes direct shell or command execution capability", tool.Name),
			Description:    "Direct command execution tools allow LLMs or prompt injection attackers to execute arbitrary system binaries on the host system.",
			Evidence:       fmt.Sprintf("Tool name: %s", tool.Name),
			Recommendation: "Constrain command execution to a strict whitelist of commands and arguments, or run within an isolated sandbox container.",
		})
	}

	// 3. Recursive check for input schema properties (including nested objects)
	propFindings := analyzeProperties(serverName, tool, tool.InputSchema.Properties, "")
	findings = append(findings, propFindings...)

	// 4. Weak Schema check: Tool has no parameters or empty schema
	if len(tool.InputSchema.Properties) == 0 && tool.InputSchema.Type == "" {
		findings = append(findings, Finding{
			Status:         StatusAttackSurface,
			Severity:       SeverityLow,
			Category:       CategoryWeakSchema,
			CWEID:          "CWE-20",
			CWETitle:       "Improper Input Validation",
			ServerName:     serverName,
			ToolName:       tool.Name,
			Title:          fmt.Sprintf("Attack Surface: Missing argument schema in tool '%s'", tool.Name),
			Description:    "The tool defines an empty or unspecified inputSchema. This reduces schema contract clarity and prevents argument validation.",
			Evidence:       fmt.Sprintf("Tool '%s' inputSchema is empty", tool.Name),
			Recommendation: "Explicitly declare inputSchema with 'type: object' and defined properties.",
		})
	}

	// 5. Tool Description Poisoning & Prompt Injection Check (OWASP LLM01)
	combinedDesc := tool.Name + " " + tool.Description
	for _, prop := range tool.InputSchema.Properties {
		combinedDesc += " " + prop.Description
	}

	if promptInjectionRegex.MatchString(combinedDesc) {
		findings = append(findings, Finding{
			Status:         StatusConfirmed,
			Severity:       SeverityCritical,
			Category:       CategoryToolPoisoning,
			CWEID:          "CWE-1021",
			CWETitle:       "Improper Restriction of Rendered UI Layers / Prompt Injection",
			ServerName:     serverName,
			ToolName:       tool.Name,
			Title:          fmt.Sprintf("CONFIRMED: Tool '%s' contains Prompt Hijacking / Tool Poisoning instructions", tool.Name),
			Description:    "The tool description or schema contains explicit directives aimed at overriding or hijacking the calling LLM's system instructions (OWASP LLM01).",
			Evidence:       fmt.Sprintf("Matched pattern: %s", promptInjectionRegex.FindString(combinedDesc)),
			Recommendation: "CRITICAL: Reject this tool. Tool metadata must not contain prompt manipulation, override triggers, or jailbreak patterns.",
		})
	}

	if hiddenUnicodeRegex.MatchString(combinedDesc) {
		findings = append(findings, Finding{
			Status:         StatusConfirmed,
			Severity:       SeverityHigh,
			Category:       CategoryToolPoisoning,
			CWEID:          "CWE-1021",
			CWETitle:       "Invisible Unicode Formatting in Tool Metadata",
			ServerName:     serverName,
			ToolName:       tool.Name,
			Title:          fmt.Sprintf("CONFIRMED: Tool '%s' contains hidden zero-width / bidirectional Unicode characters", tool.Name),
			Description:    "Zero-width or RTL override Unicode characters (e.g. \\u200B, \\u202E) detected in tool metadata. These are frequently used to conceal malicious prompt injections from human operators.",
			Evidence:       "Hidden Unicode characters detected in tool description/schema.",
			Recommendation: "Sanitize tool metadata by stripping zero-width spaces, RTL overrides, and other non-printable formatting characters.",
		})
	}

	return findings
}

func analyzeProperties(serverName string, tool protocol.Tool, properties map[string]protocol.PropertyDef, pathPrefix string) []Finding {
	var findings []Finding

	for propName, propDef := range properties {
		fullPath := propName
		if pathPrefix != "" {
			fullPath = pathPrefix + "." + propName
		}

		propDesc := propDef.Description
		propType := propDef.TypeString()

		// RCE / Shell parameter check
		if rceParamRegex.MatchString(propName) {
			findings = append(findings, Finding{
				Status:         StatusAttackSurface,
				Severity:       SeverityHigh,
				Category:       CategoryRCE,
				CWEID:          "CWE-78",
				CWETitle:       "OS Command Injection",
				ServerName:     serverName,
				ToolName:       tool.Name,
				ParameterName:  propName,
				ParameterPath:  fullPath,
				Title:          fmt.Sprintf("Attack Surface: Parameter '%s' in tool '%s' accepts command/code input", fullPath, tool.Name),
				Description:    "The parameter name indicates that raw commands, scripts, or code may be accepted. Requires dynamic verification via tools/call.",
				Evidence:       fmt.Sprintf("Parameter '%s' (type: %s): %s", fullPath, propType, propDesc),
				Recommendation: "Avoid passing arbitrary shell strings. Use parameterized structured arguments with predefined enum choices.",
			})
		}

		// Path Traversal / Arbitrary File Access check
		if fileParamRegex.MatchString(propName) {
			hasEnum := len(propDef.Enum) > 0
			if !hasEnum {
				hasContainment := containmentHintsRegex.MatchString(propDesc) || containmentHintsRegex.MatchString(tool.Description)
				isTemp := tempFilespaceRegex.MatchString(propName) || tempFilespaceRegex.MatchString(propDesc)

				sev := SeverityMedium
				desc := "The parameter accepts file or directory paths without an enum restriction. Requires dynamic tools/call testing to verify path traversal."
				if hasContainment {
					sev = SeverityLow
					desc = "The parameter accepts file paths with declared workspace/sandbox containment. Dynamic probe will verify boundary enforcement."
				} else if isTemp {
					sev = SeverityInfo
					desc = "Internal pipeline reference for temporary/generated files. Typically evaluated within local stdio process namespace."
				}

				findings = append(findings, Finding{
					Status:         StatusAttackSurface,
					Severity:       sev,
					Category:       CategoryPathTraversal,
					CWEID:          "CWE-22",
					CWETitle:       "Improper Limitation of a Pathname to a Restricted Directory",
					ServerName:     serverName,
					ToolName:       tool.Name,
					ParameterName:  propName,
					ParameterPath:  fullPath,
					Title:          fmt.Sprintf("Attack Surface: File path parameter '%s' in tool '%s'", fullPath, tool.Name),
					Description:    desc,
					Evidence:       fmt.Sprintf("Parameter '%s' (type: %s)", fullPath, propType),
					Recommendation: "Enforce strict base-directory sandboxing (e.g., filepath.Clean and filepath.Rel check against an allowed root directory).",
				})
			}
		}

		// SSRF check
		if ssrfParamRegex.MatchString(propName) {
			findings = append(findings, Finding{
				Status:         StatusAttackSurface,
				Severity:       SeverityMedium,
				Category:       CategorySSRF,
				CWEID:          "CWE-918",
				CWETitle:       "Server-Side Request Forgery (SSRF)",
				ServerName:     serverName,
				ToolName:       tool.Name,
				ParameterName:  propName,
				ParameterPath:  fullPath,
				Title:          fmt.Sprintf("Attack Surface: Network endpoint parameter '%s' in tool '%s'", fullPath, tool.Name),
				Description:    "The tool accepts target URLs/endpoints. Requires dynamic verification to test private/loopback IP restrictions.",
				Evidence:       fmt.Sprintf("Parameter '%s' (type: %s)", fullPath, propType),
				Recommendation: "Validate URLs against an allowlist of protocols and domains. Block private and loopback IP ranges.",
			})
		}

		// SQL Injection check
		if sqliParamRegex.MatchString(propName) {
			findings = append(findings, Finding{
				Status:         StatusAttackSurface,
				Severity:       SeverityMedium,
				Category:       CategorySQLi,
				CWEID:          "CWE-89",
				CWETitle:       "SQL Injection",
				ServerName:     serverName,
				ToolName:       tool.Name,
				ParameterName:  propName,
				ParameterPath:  fullPath,
				Title:          fmt.Sprintf("Attack Surface: SQL query parameter '%s' in tool '%s'", fullPath, tool.Name),
				Description:    "Passing unparameterized SQL strings creates SQL injection risks if input is influenced by untrusted data.",
				Evidence:       fmt.Sprintf("Parameter '%s' (type: %s)", fullPath, propType),
				Recommendation: "Use parameterized queries or ORM abstractions instead of accepting arbitrary raw SQL strings.",
			})
		}

		// Recursive traversal for nested object properties
		if len(propDef.Properties) > 0 {
			nestedFindings := analyzeProperties(serverName, tool, propDef.Properties, fullPath)
			findings = append(findings, nestedFindings...)
		}
	}

	return findings
}

func maskSecret(val string) string {
	if len(val) <= 6 {
		return "******"
	}
	return val[:3] + "..." + val[len(val)-3:]
}
