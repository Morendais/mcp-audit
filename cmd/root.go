package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	globalTimeout time.Duration
	verbose       bool
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "mcp-hunter",
	Short: "mcp-hunter: Developer security scanner and DAST fuzzer for Model Context Protocol (MCP) servers",
	Long: `mcp-hunter is a zero-config security auditing and dynamic verification CLI utility for MCP servers.
When run without arguments, it automatically scans for local Claude Desktop, Cursor, and Windsurf
configurations and presents an interactive express audit menu.

It can also audit direct server commands via --exec, remote SSE endpoints, and export SARIF 2.1.0 reports for CI/CD.`,
	SilenceUsage: true,
	RunE:         runRootDefault,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().DurationVar(&globalTimeout, "timeout", 15*time.Second, "Timeout for server interactions (e.g. 10s, 30s, 1m)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose debug output")
	RootCmd.Flags().StringVarP(&execCmdFlag, "exec", "e", "", "Directly execute and audit a server command")
	RootCmd.Flags().StringVarP(&configPathFlag, "config", "c", "", "Path to custom MCP config file (JSON)")
}
