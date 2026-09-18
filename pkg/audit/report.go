package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CalculateStats tallies findings by severity level and status.
func CalculateStats(findings []Finding) Stats {
	var s Stats
	for _, f := range findings {
		switch f.Status {
		case StatusConfirmed:
			s.Confirmed++
		case StatusAttackSurface:
			s.AttackSurface++
		case StatusDefended:
			s.Defended++
		}

		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// FormatConsole renders the security findings in human-readable colored ANSI format.
func FormatConsole(report AuditReport) string {
	var sb strings.Builder

	sb.WriteString("\n" + strings.Repeat("═", 78) + "\n")
	sb.WriteString("                       \033[1;31mMCP SECURITY AUDIT REPORT\033[0m\n")
	sb.WriteString(strings.Repeat("═", 78) + "\n\n")

	sb.WriteString(fmt.Sprintf("  \033[1mServers Audited:\033[0m %-4d | \033[1mTools Analyzed:\033[0m %-4d\n", report.TotalServers, report.TotalTools))
	sb.WriteString(fmt.Sprintf("  \033[1;41;37m CONFIRMED VULNERABILITIES: %d \033[0m  \033[1;33mATTACK SURFACE: %d\033[0m  \033[1;32mDEFENDED: %d\033[0m\n",
		report.Stats.Confirmed, report.Stats.AttackSurface, report.Stats.Defended))
	sb.WriteString(fmt.Sprintf("  Breakdown: \033[1;31mCRITICAL:\033[0m %d  \033[1;33mHIGH:\033[0m %d  \033[1;34mMEDIUM:\033[0m %d  \033[32mLOW:\033[0m %d  \033[37mINFO:\033[0m %d\n",
		report.Stats.Critical, report.Stats.High, report.Stats.Medium, report.Stats.Low, report.Stats.Info))
	sb.WriteString(strings.Repeat("─", 78) + "\n\n")

	if len(report.Findings) == 0 {
		sb.WriteString("  \033[1;32m[✓] No attack surface or security issues identified.\033[0m\n\n")
		return sb.String()
	}

	for i, f := range report.Findings {
		statusBadge := formatStatusBadge(f.Status)
		sevBadge := severityBadge(f.Severity)

		sb.WriteString(fmt.Sprintf("  [%d] %s %s \033[1m%s\033[0m\n", i+1, statusBadge, sevBadge, f.Title))
		sb.WriteString(fmt.Sprintf("      \033[2mCategory:\033[0m       %s\n", f.Category))
		if f.ServerName != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mServer:\033[0m         %s\n", f.ServerName))
		}
		if f.ToolName != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mTool:\033[0m           %s\n", f.ToolName))
		}
		if f.ParameterName != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mParameter:\033[0m      %s\n", f.ParameterName))
		}
		sb.WriteString(fmt.Sprintf("      \033[2mDescription:\033[0m    %s\n", f.Description))
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mEvidence:\033[0m       %s\n", f.Evidence))
		}
		if f.FuzzPayload != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mProbe Payload:\033[0m  %s\n", f.FuzzPayload))
		}
		if f.FuzzResponse != "" {
			sb.WriteString(fmt.Sprintf("      \033[2mProbe Output:\033[0m   %s\n", f.FuzzResponse))
		}
		sb.WriteString(fmt.Sprintf("      \033[1;36mRemediation:\033[0m    %s\n\n", f.Recommendation))
	}

	return sb.String()
}

func formatStatusBadge(status FindingStatus) string {
	switch status {
	case StatusConfirmed:
		return "\033[1;41;37m [VULNERABILITY CONFIRMED] \033[0m"
	case StatusAttackSurface:
		return "\033[1;33m[ATTACK SURFACE]\033[0m"
	case StatusDefended:
		return "\033[1;32m[DEFENDED]\033[0m"
	case StatusCrashed:
		return "\033[1;45;37m [CRASH BUG] \033[0m"
	default:
		return "\033[37m[AUDIT]\033[0m"
	}
}

func severityBadge(s Severity) string {
	switch s {
	case SeverityCritical:
		return "\033[1;31m(CRITICAL)\033[0m"
	case SeverityHigh:
		return "\033[1;31m(HIGH)\033[0m"
	case SeverityMedium:
		return "\033[1;33m(MEDIUM)\033[0m"
	case SeverityLow:
		return "\033[32m(LOW)\033[0m"
	default:
		return "\033[37m(INFO)\033[0m"
	}
}

// FormatJSON serializes the audit report into formatted JSON.
func FormatJSON(report AuditReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to encode JSON audit report: %w", err)
	}
	return string(data), nil
}

// FormatMarkdown outputs the findings as a clean GitHub-Flavored Markdown report.
func FormatMarkdown(report AuditReport) string {
	var sb strings.Builder

	sb.WriteString("# MCP Security Audit Report\n\n")
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Servers Audited**: %d\n", report.TotalServers))
	sb.WriteString(fmt.Sprintf("- **Total Tools Analyzed**: %d\n", report.TotalTools))
	sb.WriteString(fmt.Sprintf("- **Confirmed Vulnerabilities**: %d\n", report.Stats.Confirmed))
	sb.WriteString(fmt.Sprintf("- **Attack Surface Items**: %d\n", report.Stats.AttackSurface))
	sb.WriteString(fmt.Sprintf("- **Defended / Sanitized**: %d\n\n", report.Stats.Defended))

	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|---|---|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", report.Stats.Critical))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", report.Stats.High))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", report.Stats.Medium))
	sb.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", report.Stats.Low))
	sb.WriteString(fmt.Sprintf("| ⚪ Info | %d |\n\n", report.Stats.Info))

	sb.WriteString("## Findings Detail\n\n")

	if len(report.Findings) == 0 {
		sb.WriteString("No security vulnerabilities or unconstrained attack surface items were identified.\n")
		return sb.String()
	}

	for i, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s: %s\n\n", i+1, f.Status, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("- **Status**: `%s`\n", f.Status))
		sb.WriteString(fmt.Sprintf("- **Category**: %s\n", f.Category))
		if f.ServerName != "" {
			sb.WriteString(fmt.Sprintf("- **Server**: `%s`\n", f.ServerName))
		}
		if f.ToolName != "" {
			sb.WriteString(fmt.Sprintf("- **Tool**: `%s`\n", f.ToolName))
		}
		if f.ParameterName != "" {
			sb.WriteString(fmt.Sprintf("- **Parameter**: `%s`\n", f.ParameterName))
		}
		sb.WriteString(fmt.Sprintf("- **Description**: %s\n", f.Description))
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("- **Evidence**: `%s`\n", f.Evidence))
		}
		if f.FuzzPayload != "" {
			sb.WriteString(fmt.Sprintf("- **Probe Payload**: `%s`\n", f.FuzzPayload))
		}
		if f.FuzzResponse != "" {
			sb.WriteString(fmt.Sprintf("- **Probe Response**: `%s`\n", f.FuzzResponse))
		}
		sb.WriteString(fmt.Sprintf("- **Remediation**: %s\n\n", f.Recommendation))
		sb.WriteString("---\n\n")
	}

	return sb.String()
}
