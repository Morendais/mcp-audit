package audit

// Severity represents the criticality of a detected security issue.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Category classifies the type of vulnerability.
type Category string

const (
	CategoryRCE             Category = "Remote Code Execution"
	CategoryPathTraversal   Category = "Path Traversal / Arbitrary File Access"
	CategorySSRF            Category = "Server-Side Request Forgery"
	CategorySQLi            Category = "SQL Injection"
	CategorySecretLeak      Category = "Exposed Secrets & Credentials"
	CategoryExcessiveAgency Category = "Excessive Agency / Destructive Action"
	CategoryWeakSchema      Category = "Unconstrained Schema / Lack of Validation"
	CategoryToolPoisoning   Category = "Tool Poisoning / Prompt Injection"
	CategoryCrashBug        Category = "Type Confusion / Crash Bug"
)

// FindingStatus differentiates static attack surface from dynamically confirmed vulnerabilities.
type FindingStatus string

const (
	// StatusAttackSurface represents a potential vector detected by schema/name analysis.
	StatusAttackSurface FindingStatus = "ATTACK_SURFACE"

	// StatusConfirmed represents an issue verified by an active non-destructive tools/call payload.
	StatusConfirmed FindingStatus = "CONFIRMED_VULNERABILITY"

	// StatusDefended means active testing revealed the server rejected or sanitized the payload.
	StatusDefended FindingStatus = "DEFENDED"

	// StatusPrerequisiteFailed indicates the tool requires unconfigured state or credentials to execute.
	StatusPrerequisiteFailed FindingStatus = "PREREQUISITE_FAILED"

	// StatusCrashed indicates the server process crashed during active testing.
	StatusCrashed FindingStatus = "CRASH_BUG"
)

// Finding represents a single identified security risk or vulnerability.
type Finding struct {
	Status             FindingStatus `json:"status"`
	Severity           Severity      `json:"severity"`
	Category           Category      `json:"category"`
	CWEID              string        `json:"cweId,omitempty"`
	CWETitle           string        `json:"cweTitle,omitempty"`
	ServerName         string        `json:"serverName,omitempty"`
	ToolName           string        `json:"toolName,omitempty"`
	ParameterName      string        `json:"parameterName,omitempty"`
	ParameterPath      string        `json:"parameterPath,omitempty"` // For nested properties, e.g. "options.file.path"
	Title              string        `json:"title"`
	Description        string        `json:"description"`
	Evidence           string        `json:"evidence,omitempty"`
	FuzzPayload        string        `json:"fuzzPayload,omitempty"`
	FuzzResponse       string        `json:"fuzzResponse,omitempty"`
	Recommendation     string        `json:"recommendation"`
}

// AuditReport summarizes findings for an entire audit session.
type AuditReport struct {
	TotalServers int       `json:"totalServers"`
	TotalTools   int       `json:"totalTools"`
	Findings     []Finding `json:"findings"`
	Stats        Stats     `json:"stats"`
}

// Stats provides a breakdown of findings by severity and verification status.
type Stats struct {
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	Info               int `json:"info"`
	Confirmed          int `json:"confirmed"`
	AttackSurface      int `json:"attackSurface"`
	Defended           int `json:"defended"`
	PrerequisiteFailed int `json:"prerequisiteFailed"`
}
