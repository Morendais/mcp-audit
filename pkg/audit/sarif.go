package audit

import (
	"encoding/json"
	"fmt"
)

// SARIFReport represents the OASIS SARIF v2.1.0 JSON format for CI/CD integration.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFToolComponent `json:"tool"`
	Results []SARIFResult      `json:"results"`
}

type SARIFToolComponent struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFDescription `json:"shortDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       SARIFRuleProps   `json:"properties,omitempty"`
}

type SARIFRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFDescription struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"` // "error", "warning", "note"
	Message   SARIFDescription `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// FormatSARIF converts an AuditReport into standard OASIS SARIF v2.1.0 format.
func FormatSARIF(report AuditReport) (string, error) {
	ruleMap := make(map[string]SARIFRule)
	var results []SARIFResult

	for _, f := range report.Findings {
		// Do not report defended endpoints as security alerts in SARIF
		if f.Status == StatusDefended {
			continue
		}

		cweID := f.CWEID
		if cweID == "" {
			cweID = defaultCWE(f.Category)
		}
		ruleID := fmt.Sprintf("MCP-%s", cweID)

		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = SARIFRule{
				ID:   ruleID,
				Name: string(f.Category),
				ShortDescription: SARIFDescription{
					Text: f.Title,
				},
				HelpURI: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweIDNum(cweID)),
				Properties: SARIFRuleProps{
					Tags: []string{"security", cweID},
				},
			}
		}

		level := "warning"
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			level = "error"
		} else if f.Severity == SeverityLow || f.Severity == SeverityInfo {
			level = "note"
		}

		targetURI := fmt.Sprintf("mcp://%s/%s", f.ServerName, f.ToolName)
		if f.ParameterName != "" {
			targetURI += "/" + f.ParameterName
		}

		msg := fmt.Sprintf("[%s] %s: %s", f.Status, f.Title, f.Description)
		if f.Recommendation != "" {
			msg += " Remediation: " + f.Recommendation
		}

		results = append(results, SARIFResult{
			RuleID: ruleID,
			Level:  level,
			Message: SARIFDescription{
				Text: msg,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: targetURI,
						},
					},
				},
			},
		})
	}

	rulesList := make([]SARIFRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rulesList = append(rulesList, r)
	}

	sarif := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFToolComponent{
					Driver: SARIFDriver{
						Name:           "mcp-hunter",
						Version:        "0.1.0",
						InformationURI: "https://github.com/mcp-hunter/mcp-hunter",
						Rules:          rulesList,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to encode SARIF report: %w", err)
	}

	return string(data), nil
}

func defaultCWE(cat Category) string {
	switch cat {
	case CategoryRCE:
		return "CWE-78"
	case CategoryPathTraversal:
		return "CWE-22"
	case CategorySSRF:
		return "CWE-918"
	case CategorySQLi:
		return "CWE-89"
	case CategorySecretLeak:
		return "CWE-798"
	case CategoryExcessiveAgency:
		return "CWE-250"
	default:
		return "CWE-20"
	}
}

func cweIDNum(cwe string) string {
	var num string
	for _, r := range cwe {
		if r >= '0' && r <= '9' {
			num += string(r)
		}
	}
	if num == "" {
		return "20"
	}
	return num
}
