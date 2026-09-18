package audit

import (
	"errors"
	"strings"
	"testing"
)

func TestEvaluateServerScorecard_Green(t *testing.T) {
	findings := []Finding{
		{
			Status:   StatusDefended,
			Severity: SeverityInfo,
			Category: CategoryPathTraversal,
			CWEID:    "CWE-22",
			Title:    "DEFENDED: Path traversal rejected",
			ToolName: "read_file",
		},
	}
	sc := EvaluateServerScorecard("test-srv", "Claude Desktop", "npx test", 1, findings, nil)
	if sc.Status != StatusGreen {
		t.Fatalf("expected StatusGreen, got %s", sc.Status)
	}
	if !strings.Contains(sc.Headline, "CWE-22 defended") {
		t.Errorf("expected headline to contain 'CWE-22 defended', got %s", sc.Headline)
	}
}

func TestEvaluateServerScorecard_Red(t *testing.T) {
	findings := []Finding{
		{
			Status:   StatusConfirmed,
			Severity: SeverityCritical,
			Category: CategoryPathTraversal,
			CWEID:    "CWE-22",
			Title:    "CONFIRMED: Arbitrary File Read",
			ToolName: "read_file",
		},
	}
	sc := EvaluateServerScorecard("vuln-srv", "Cursor", "node server.js", 1, findings, nil)
	if sc.Status != StatusRed {
		t.Fatalf("expected StatusRed, got %s", sc.Status)
	}
	if !strings.Contains(sc.Headline, "Uncontrolled filesystem access detected") {
		t.Errorf("expected headline to contain critical traversal warning, got %s", sc.Headline)
	}
}

func TestEvaluateServerScorecard_Yellow(t *testing.T) {
	findings := []Finding{
		{
			Status:   StatusCrashed,
			Severity: SeverityHigh,
			Category: CategoryCrashBug,
			CWEID:    "CWE-20",
			Title:    "CRASH BUG: Unhandled null pointer",
			ToolName: "parse_data",
		},
	}
	sc := EvaluateServerScorecard("crash-srv", "Local", "python srv.py", 1, findings, nil)
	if sc.Status != StatusYellow {
		t.Fatalf("expected StatusYellow, got %s", sc.Status)
	}
	if !strings.Contains(sc.Headline, "Unhandled crash bug") {
		t.Errorf("expected headline to contain crash bug warning, got %s", sc.Headline)
	}
}

func TestEvaluateServerScorecard_AuthBlocked(t *testing.T) {
	err := errors.New("initialization failed: missing API token or authorization header")
	sc := EvaluateServerScorecard("auth-srv", "Claude Desktop", "srv", 0, nil, err)
	if sc.Status != StatusGray {
		t.Fatalf("expected StatusGray, got %s", sc.Status)
	}
	if !strings.Contains(sc.Headline, "Authentication required") {
		t.Errorf("expected headline to mention Authentication required, got %s", sc.Headline)
	}
}

func TestFormatScorecard(t *testing.T) {
	cards := []ServerScorecard{
		{
			Name:       "safe-srv",
			Status:     StatusGreen,
			Headline:   "Secure (CWE-22 defended)",
			ToolsCount: 2,
		},
		{
			Name:       "vuln-srv",
			Status:     StatusRed,
			Headline:   "Arbitrary command execution detected (CRITICAL)",
			Details:    []string{"RCE in tool 'run_cmd'"},
			ToolsCount: 1,
		},
	}
	out := FormatScorecard(cards)
	if !strings.Contains(out, "MCP SECURITY SCORECARD") {
		t.Errorf("expected header in output")
	}
	if !strings.Contains(out, "safe-srv") || !strings.Contains(out, "vuln-srv") {
		t.Errorf("expected server names in output")
	}
	if !strings.Contains(out, "Total: 2") || !strings.Contains(out, "Secure: 1") || !strings.Contains(out, "Critical: 1") {
		t.Errorf("expected summary line with counts, got:\n%s", out)
	}
}
