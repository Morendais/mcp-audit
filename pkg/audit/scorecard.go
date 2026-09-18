package audit

import (
	"fmt"
	"strings"
)

// ServerStatus describes the high-level traffic-light status of a server.
type ServerStatus string

const (
	StatusGreen  ServerStatus = "SECURE"
	StatusRed    ServerStatus = "CRITICAL"
	StatusYellow ServerStatus = "WARNING"
	StatusGray   ServerStatus = "BLOCKED"
)

// ServerScorecard summarizes the security posture of an individual MCP server.
type ServerScorecard struct {
	Name       string
	Source     string
	Command    string
	ToolsCount int
	Status     ServerStatus
	Headline   string
	Details    []string
	Error      error
}

// EvaluateServerScorecard produces a clean traffic-light scorecard from audit findings.
func EvaluateServerScorecard(name, source, cmdStr string, toolsCount int, findings []Finding, err error) ServerScorecard {
	sc := ServerScorecard{
		Name:       name,
		Source:     source,
		Command:    cmdStr,
		ToolsCount: toolsCount,
	}

	if err != nil {
		sc.Status = StatusGray
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "auth") ||
			strings.Contains(strings.ToLower(errStr), "token") ||
			strings.Contains(strings.ToLower(errStr), "key") ||
			strings.Contains(strings.ToLower(errStr), "credential") {
			sc.Headline = "Authentication required (missing API keys or tokens)"
		} else {
			sc.Headline = fmt.Sprintf("Failed to initialize (%v)", err)
		}
		return sc
	}

	var confirmedFindings []Finding
	var crashFindings []Finding
	var defendedCount int

	for _, f := range findings {
		switch f.Status {
		case StatusConfirmed:
			confirmedFindings = append(confirmedFindings, f)
		case StatusCrashed:
			crashFindings = append(crashFindings, f)
		case StatusDefended:
			defendedCount++
		}
	}

	// 1. Check for confirmed exploits (RED)
	if len(confirmedFindings) > 0 {
		sc.Status = StatusRed
		top := confirmedFindings[0]
		switch {
		case strings.Contains(top.CWEID, "22"):
			sc.Headline = "Uncontrolled filesystem access detected (CRITICAL)"
		case strings.Contains(top.CWEID, "78"):
			sc.Headline = "Arbitrary command execution detected (CRITICAL)"
		case strings.Contains(top.CWEID, "918"):
			sc.Headline = "Server-Side Request Forgery detected (CRITICAL)"
		case strings.Contains(top.CWEID, "89"):
			sc.Headline = "SQL Injection detected (CRITICAL)"
		case strings.Contains(top.CWEID, "1021"):
			sc.Headline = "Prompt hijacking / LLM override detected (HIGH)"
		default:
			sc.Headline = fmt.Sprintf("%s (%s)", top.Title, top.Severity)
		}

		for _, cf := range confirmedFindings {
			sc.Details = append(sc.Details, fmt.Sprintf("Confirmed exploit: %s in tool %q", cf.Title, cf.ToolName))
		}
		return sc
	}

	// 2. Check for crash bugs (YELLOW)
	if len(crashFindings) > 0 {
		sc.Status = StatusYellow
		sc.Headline = "Unhandled crash bug on invalid input (CWE-20 DoS)"
		for _, cf := range crashFindings {
			sc.Details = append(sc.Details, fmt.Sprintf("Process crashed via %s in tool %q", cf.Title, cf.ToolName))
		}
		return sc
	}

	// 3. Defended or clean (GREEN)
	sc.Status = StatusGreen
	if defendedCount > 0 {
		sc.Headline = fmt.Sprintf("Secure (CWE-22 defended, %d tools tested)", toolsCount)
	} else if toolsCount > 0 {
		sc.Headline = fmt.Sprintf("Secure (no vulnerabilities found, %d tools inspected)", toolsCount)
	} else {
		sc.Headline = "Secure (0 tools exposed)"
	}

	return sc
}

// FormatScorecard renders an aesthetic terminal scorecard card.
func FormatScorecard(cards []ServerScorecard) string {
	var sb strings.Builder

	sb.WriteString("\n\033[1;36m" + strings.Repeat("═", 78) + "\033[0m\n")
	sb.WriteString("\033[1;37m                       MCP SECURITY SCORECARD\033[0m\n")
	sb.WriteString("\033[1;36m" + strings.Repeat("═", 78) + "\033[0m\n\n")

	greenCount := 0
	redCount := 0
	yellowCount := 0
	grayCount := 0

	for _, c := range cards {
		var badge string
		switch c.Status {
		case StatusGreen:
			greenCount++
			badge = "\033[1;32m🟢 " + c.Name + ":\033[0m \033[32m" + c.Headline + "\033[0m"
		case StatusRed:
			redCount++
			badge = "\033[1;31m🔴 " + c.Name + ":\033[0m \033[1;31m" + c.Headline + "\033[0m"
		case StatusYellow:
			yellowCount++
			badge = "\033[1;33m🟡 " + c.Name + ":\033[0m \033[33m" + c.Headline + "\033[0m"
		case StatusGray:
			grayCount++
			badge = "\033[1;90m⚪ " + c.Name + ":\033[0m \033[90m" + c.Headline + "\033[0m"
		}

		sb.WriteString(badge + "\n")
		for _, d := range c.Details {
			sb.WriteString(fmt.Sprintf("   \033[2m└─ %s\033[0m\n", d))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\033[1;36m" + strings.Repeat("─", 78) + "\033[0m\n")
	sb.WriteString(fmt.Sprintf("\033[1;37mSUMMARY:\033[0m Total: %d | \033[32mSecure: %d\033[0m | \033[31mCritical: %d\033[0m | \033[33mWarning: %d\033[0m | \033[90mBlocked: %d\033[0m\n",
		len(cards), greenCount, redCount, yellowCount, grayCount))
	sb.WriteString("\033[2mTip: Run with --verbose for full JSON-RPC traces or --sarif report.sarif for CI/CD.\033[0m\n")
	sb.WriteString("\033[1;36m" + strings.Repeat("═", 78) + "\033[0m\n\n")

	return sb.String()
}
