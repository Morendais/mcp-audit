package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"mcp-audit/pkg/audit"
	"mcp-audit/pkg/protocol"

	"github.com/spf13/cobra"
)

var (
	remoteFormat string
	remoteOutput string
	runAudit     bool
)

var remoteCmd = &cobra.Command{
	Use:   "remote <url>",
	Short: "Audit a remote MCP server over HTTP/SSE",
	Long: `Connects to an external or remote MCP server via HTTP/SSE, completes the protocol handshake,
retrieves the tool list, and runs security vulnerability analysis on exposed tools and argument schemas.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemote,
}

func init() {
	RootCmd.AddCommand(remoteCmd)
	remoteCmd.Flags().StringVarP(&remoteFormat, "format", "f", "console", "Output format (console, json, markdown, sarif)")
	remoteCmd.Flags().StringVarP(&remoteOutput, "output", "o", "", "File path to save the generated report")
	remoteCmd.Flags().BoolVar(&runAudit, "audit", true, "Execute security vulnerability rules on discovered tools")
}

func runRemote(cmd *cobra.Command, args []string) error {
	targetURL := args[0]
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	fmt.Printf("\033[1;34m[+] Connecting to remote MCP server:\033[0m %s\n", targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	client, err := protocol.NewSSEClient(ctx, targetURL)
	if err != nil {
		return fmt.Errorf("failed to establish SSE connection: %w", err)
	}
	defer client.Close()

	clientInfo := protocol.ClientInfo{
		Name:    "mcp-audit",
		Version: "0.2.0",
	}

	initResult, err := client.Initialize(ctx, clientInfo)
	if err != nil {
		return fmt.Errorf("remote handshake 'initialize' failed: %w", err)
	}

	serverName := initResult.ServerInfo.Name
	if serverName == "" {
		serverName = "remote-server"
	}
	serverVer := initResult.ServerInfo.Version
	if serverVer == "" {
		serverVer = "unknown"
	}

	fmt.Printf("  \033[1;32m[✓] Connected:\033[0m %s (v%s), Protocol: %s\n", serverName, serverVer, initResult.ProtocolVersion)

	tools, err := client.ListTools(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve tools from remote server: %w", err)
	}

	fmt.Printf("  \033[1;32m[✓] Tools discovered:\033[0m %d\n\n", len(tools))

	var allFindings []audit.Finding
	if runAudit {
		for _, tool := range tools {
			findings := audit.AnalyzeTool(serverName, tool)
			allFindings = append(allFindings, findings...)
		}
	}

	report := audit.AuditReport{
		TotalServers: 1,
		TotalTools:   len(tools),
		Findings:     allFindings,
		Stats:        audit.CalculateStats(allFindings),
	}

	var outputContent string
	switch strings.ToLower(remoteFormat) {
	case "json":
		outputContent, err = audit.FormatJSON(report)
		if err != nil {
			return err
		}
	case "sarif":
		outputContent, err = audit.FormatSARIF(report)
		if err != nil {
			return err
		}
	case "markdown", "md":
		outputContent = audit.FormatMarkdown(report)
	default:
		outputContent = audit.FormatConsole(report)
	}

	if remoteOutput != "" {
		if err := os.WriteFile(remoteOutput, []byte(outputContent), 0644); err != nil {
			return fmt.Errorf("failed to write report to %q: %w", remoteOutput, err)
		}
		fmt.Printf("\033[1;32m[+] Report saved to:\033[0m %s\n", remoteOutput)
	} else {
		fmt.Print(outputContent)
	}

	return nil
}
