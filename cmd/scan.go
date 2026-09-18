package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mcp-audit/pkg/audit"
	"mcp-audit/pkg/config"
	"mcp-audit/pkg/protocol"

	"github.com/spf13/cobra"
)

var (
	configPathFlag string
	targetServer   string
	localFormat    string
	localOutput    string
	sarifOutFlag   string
	localAudit     bool
	localFuzz      bool
	execCmdFlag    string
	failOnFlag     string
)

// scanCmd represents the security scan command
var scanCmd = &cobra.Command{
	Use:     "scan",
	Aliases: []string{"check", "local"},
	Short:   "Audit local MCP servers (via config file or direct --exec command)",
	Long: `The scan command audits local Model Context Protocol (MCP) servers.
It can automatically discover MCP configurations across Claude Desktop, Cursor, Cline,
and local ./mcp.json, OR audit any server process directly using the --exec flag.

Dynamic verification active probes fuzz tools/call arguments for Path Traversal (CWE-22),
Command Injection (CWE-78), SSRF (CWE-918), SQLi (CWE-89), and Type Confusion crashes (CWE-20),
outputting standard SARIF 2.1.0 for GitHub Code Scanning and CI/CD pipelines.`,
	RunE: runScan,
}

func init() {
	RootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&configPathFlag, "config", "c", "", "Path to custom MCP config file (JSON)")
	scanCmd.Flags().StringVarP(&targetServer, "server", "s", "", "Audit only a specific server by name from config")
	scanCmd.Flags().StringVarP(&execCmdFlag, "exec", "e", "", "Directly execute and audit a server command (e.g. --exec \"npx @modelcontextprotocol/server-filesystem /tmp\")")
	scanCmd.Flags().StringVarP(&localFormat, "format", "f", "console", "Output report format (console, json, markdown, sarif)")
	scanCmd.Flags().StringVarP(&localOutput, "output", "o", "", "Save report to specified file path")
	scanCmd.Flags().StringVar(&sarifOutFlag, "sarif", "", "Shortcut to export SARIF 2.1.0 report directly to file")
	scanCmd.Flags().StringVar(&failOnFlag, "fail-on", "", "Exit with code 1 if findings meet severity threshold (critical, high, medium, any)")
	scanCmd.Flags().BoolVar(&localAudit, "audit", true, "Execute security analysis rules on servers and argument schemas")
	scanCmd.Flags().BoolVar(&localFuzz, "fuzz", true, "Perform active dynamic verification probes via tools/call")
}

func runScan(cmd *cobra.Command, args []string) error {
	var (
		serverMap    map[string]config.ServerConfig
		sourceOrigin string
	)

	// Mode 1: Direct command execution via --exec
	if execCmdFlag != "" {
		parts := parseCommandLine(execCmdFlag)
		if len(parts) == 0 {
			return fmt.Errorf("empty --exec command string")
		}
		binName := filepath.Base(parts[0])
		srvName := strings.TrimSuffix(binName, filepath.Ext(binName))
		if srvName == "" {
			srvName = "exec-target"
		}

		serverMap = map[string]config.ServerConfig{
			srvName: {
				Command: parts[0],
				Args:    parts[1:],
			},
		}
		sourceOrigin = fmt.Sprintf("Direct command (--exec %q)", execCmdFlag)
	} else {
		// Mode 2: Configuration file discovery
		resolvedPath := configPathFlag
		if resolvedPath == "" {
			detectedPath, sourceName, err := config.AutoDiscoverConfig()
			if err != nil {
				return err
			}
			resolvedPath = detectedPath
			sourceOrigin = fmt.Sprintf("%s (%s)", sourceName, resolvedPath)
		} else {
			sourceOrigin = resolvedPath
		}

		cfg, err := config.LoadClaudeConfig(resolvedPath)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}
		serverMap = cfg.MCPServers
	}

	if sarifOutFlag != "" {
		localFormat = "sarif"
		localOutput = sarifOutFlag
	}

	isConsole := strings.ToLower(localFormat) == "console"

	if isConsole {
		fmt.Printf("\033[1;34m[+] Target Source:\033[0m %s\n", sourceOrigin)
		fmt.Printf("\033[1;34m[+] Servers configured:\033[0m %d\n", len(serverMap))
		fmt.Printf("\033[1;34m[+] Mode:\033[0m Static Analysis=%t | Dynamic Verification Fuzzing=%t\n\n", localAudit, localFuzz)
	}

	var serverNames []string
	for name := range serverMap {
		if targetServer == "" || name == targetServer {
			serverNames = append(serverNames, name)
		}
	}
	sort.Strings(serverNames)

	if len(serverNames) == 0 {
		if targetServer != "" {
			return fmt.Errorf("server %q not found in configuration", targetServer)
		}
		return fmt.Errorf("no MCP servers found to audit")
	}

	var allFindings []audit.Finding
	totalTools := 0
	successful := 0
	failed := 0

	for _, name := range serverNames {
		srv := serverMap[name]
		tools, findings, err := auditServer(name, srv, isConsole, localAudit, localFuzz)
		if err != nil {
			failed++
			if isConsole {
				fmt.Printf("  \033[1;31m[✗] Server error:\033[0m %v\n\n", err)
			}
			continue
		}
		successful++
		totalTools += len(tools)
		allFindings = append(allFindings, findings...)
	}

	report := audit.AuditReport{
		TotalServers: len(serverNames),
		TotalTools:   totalTools,
		Findings:     allFindings,
		Stats:        audit.CalculateStats(allFindings),
	}

	var outputContent string
	switch strings.ToLower(localFormat) {
	case "json":
		outputContent, err := audit.FormatJSON(report)
		if err != nil {
			return err
		}
		if localOutput != "" {
			if err := os.WriteFile(localOutput, []byte(outputContent), 0644); err != nil {
				return fmt.Errorf("failed to write report to %q: %w", localOutput, err)
			}
			fmt.Printf("\033[1;32m[+] Report saved to:\033[0m %s\n", localOutput)
		} else {
			fmt.Println(outputContent)
		}

	case "sarif":
		outputContent, err := audit.FormatSARIF(report)
		if err != nil {
			return err
		}
		if localOutput != "" {
			if err := os.WriteFile(localOutput, []byte(outputContent), 0644); err != nil {
				return fmt.Errorf("failed to write report to %q: %w", localOutput, err)
			}
			fmt.Printf("\033[1;32m[+] SARIF report saved to:\033[0m %s\n", localOutput)
		} else {
			fmt.Println(outputContent)
		}

	case "markdown", "md":
		outputContent = audit.FormatMarkdown(report)
		if localOutput != "" {
			if err := os.WriteFile(localOutput, []byte(outputContent), 0644); err != nil {
				return fmt.Errorf("failed to write report to %q: %w", localOutput, err)
			}
			fmt.Printf("\033[1;32m[+] Report saved to:\033[0m %s\n", localOutput)
		} else {
			fmt.Println(outputContent)
		}

	default:
		printSummary(len(serverNames), successful, failed, totalTools)
		if localAudit {
			outputContent = audit.FormatConsole(report)
			fmt.Print(outputContent)
		}
		if localOutput != "" {
			_ = os.WriteFile(localOutput, []byte(outputContent), 0644)
			fmt.Printf("\033[1;32m[+] Report saved to:\033[0m %s\n", localOutput)
		}
	}

	// CI/CD Failure Threshold Enforcement
	if failOnFlag != "" {
		failThreshold := strings.ToLower(failOnFlag)
		hasFailure := false
		for _, f := range allFindings {
			if f.Status != audit.StatusConfirmed {
				continue
			}
			switch failThreshold {
			case "critical":
				if f.Severity == audit.SeverityCritical {
					hasFailure = true
				}
			case "high":
				if f.Severity == audit.SeverityCritical || f.Severity == audit.SeverityHigh {
					hasFailure = true
				}
			case "medium":
				if f.Severity == audit.SeverityCritical || f.Severity == audit.SeverityHigh || f.Severity == audit.SeverityMedium {
					hasFailure = true
				}
			case "any":
				hasFailure = true
			}
			if hasFailure {
				break
			}
		}
		if hasFailure {
			return fmt.Errorf("security check failed: confirmed vulnerabilities found matching --fail-on %q", failOnFlag)
		}
	}

	return nil
}

func auditServer(name string, srv config.ServerConfig, printConsole bool, runAudit bool, runFuzz bool) ([]protocol.Tool, []audit.Finding, error) {
	if printConsole {
		fmt.Println(strings.Repeat("─", 70))
		fmt.Printf("\033[1;36mSERVER:\033[0m \033[1m%s\033[0m\n", name)
		fmt.Printf("  \033[2mCommand:\033[0m %s %s\n", srv.Command, strings.Join(srv.Args, " "))
		if len(srv.Env) > 0 {
			var envKeys []string
			for k := range srv.Env {
				envKeys = append(envKeys, k)
			}
			sort.Strings(envKeys)
			fmt.Printf("  \033[2mEnvironment:\033[0m %s\n", strings.Join(envKeys, ", "))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	client, err := protocol.NewStdioClient(ctx, srv.Command, srv.Args, srv.Env)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start server process: %w", err)
	}
	defer client.Close()

	// Handshake: Initialize
	clientInfo := protocol.ClientInfo{
		Name:    "mcp-audit",
		Version: "0.2.0",
	}

	initResult, err := client.Initialize(ctx, clientInfo)
	if err != nil {
		if stderr := client.StderrOutput(); stderr != "" {
			return nil, nil, fmt.Errorf("%w\n  Process stderr: %s", err, strings.TrimSpace(stderr))
		}
		return nil, nil, err
	}

	serverVersion := initResult.ServerInfo.Version
	if serverVersion == "" {
		serverVersion = "unknown"
	}
	serverName := initResult.ServerInfo.Name
	if serverName == "" {
		serverName = name
	}

	if printConsole {
		fmt.Printf("  \033[1;32m[✓] Connected:\033[0m %s (v%s), Protocol: %s\n",
			serverName, serverVersion, initResult.ProtocolVersion)
	}

	// Query tools: ListTools
	tools, err := client.ListTools(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list tools: %w", err)
	}

	if printConsole {
		fmt.Printf("  \033[1;32m[✓] Tools found:\033[0m %d\n\n", len(tools))
		printToolsTree(tools)
	}

	var serverFindings []audit.Finding
	if runAudit {
		for _, tool := range tools {
			toolFindings := audit.AnalyzeTool(name, tool)

			// If dynamic fuzzing is enabled, perform tools/call probes
			if runFuzz {
				for _, f := range toolFindings {
					fuzzed := audit.FuzzTool(ctx, client, tool, f)
					serverFindings = append(serverFindings, fuzzed)
					if printConsole && fuzzed.Status == audit.StatusConfirmed {
						fmt.Printf("  \033[1;41;37m [!] VULNERABILITY CONFIRMED via tools/call: \033[0m \033[1m%s\033[0m\n", fuzzed.Title)
					}
				}
			} else {
				serverFindings = append(serverFindings, toolFindings...)
			}
		}
	}

	return tools, serverFindings, nil
}

func printToolsTree(tools []protocol.Tool) {
	if len(tools) == 0 {
		fmt.Println("    \033[2m(No tools exposed by this server)\033[0m")
		return
	}

	for i, tool := range tools {
		fmt.Printf("    \033[1;35m[%d] Tool:\033[0m \033[1m%s\033[0m\n", i+1, tool.Name)
		if tool.Description != "" {
			fmt.Printf("        \033[2mDescription:\033[0m %s\n", formatDescription(tool.Description))
		}

		schema := tool.InputSchema
		if len(schema.Properties) > 0 {
			var propNames []string
			for pName := range schema.Properties {
				propNames = append(propNames, pName)
			}
			sort.Strings(propNames)

			fmt.Println("        \033[2mParameters:\033[0m")
			for _, pName := range propNames {
				prop := schema.Properties[pName]
				required := ""
				for _, req := range schema.Required {
					if req == pName {
						required = " \033[31m(required)\033[0m"
						break
					}
				}
				fmt.Printf("          • \033[1m%s\033[0m \033[2m(%s)%s\033[0m\n", pName, prop.Type, required)
			}
		} else {
			fmt.Println("        \033[2mParameters: None\033[0m")
		}
		fmt.Println()
	}
}

func parseCommandLine(cmdStr string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := byte(0)

	for i := 0; i < len(cmdStr); i++ {
		c := cmdStr[i]
		if (c == '"' || c == '\'') && !inQuotes {
			inQuotes = true
			quoteChar = c
			continue
		}
		if inQuotes && c == quoteChar {
			inQuotes = false
			quoteChar = 0
			continue
		}
		if !inQuotes && (c == ' ' || c == '\t') {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func formatDescription(desc string) string {
	desc = strings.TrimSpace(desc)
	lines := strings.Split(desc, "\n")
	if len(lines) == 1 {
		return desc
	}
	return lines[0] + " \033[2m(more...)\033[0m"
}

func printSummary(total, success, failed, totalTools int) {
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("\033[1;37mAUDIT SUMMARY\033[0m\n")
	fmt.Printf("  Total Servers Audited: %d\n", total)
	fmt.Printf("  \033[32mSuccessful:\033[0m            %d\n", success)
	if failed > 0 {
		fmt.Printf("  \033[31mFailed:\033[0m                %d\n", failed)
	} else {
		fmt.Printf("  Failed:                0\n")
	}
	fmt.Printf("  Total Tools Extracted: %d\n", totalTools)
	fmt.Println(strings.Repeat("═", 70))
}
