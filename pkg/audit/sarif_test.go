package audit

import (
	"encoding/json"
	"testing"
)

func TestFormatSARIF(t *testing.T) {
	report := AuditReport{
		TotalServers: 1,
		TotalTools:   2,
		Findings: []Finding{
			{
				Status:        StatusConfirmed,
				Severity:      SeverityCritical,
				Category:      CategoryPathTraversal,
				CWEID:         "CWE-22",
				ServerName:    "file-server",
				ToolName:      "read_file",
				ParameterName: "filepath",
				Title:         "Arbitrary File Read",
				Description:   "Returns /etc/passwd contents",
			},
			{
				Status:        StatusDefended,
				Severity:      SeverityInfo,
				Category:      CategoryRCE,
				CWEID:         "CWE-78",
				ServerName:    "cmd-server",
				ToolName:      "exec",
				ParameterName: "cmd",
				Title:         "Command execution defended",
			},
		},
	}

	sarifStr, err := FormatSARIF(report)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal([]byte(sarifStr), &sarif); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %q", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	// Defended findings are filtered out from security alerts in SARIF, so exactly 1 result expected
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result in SARIF (defended excluded), got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "MCP-CWE-22" {
		t.Errorf("expected rule ID MCP-CWE-22, got %q", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level 'error' for critical severity, got %q", res.Level)
	}
}
