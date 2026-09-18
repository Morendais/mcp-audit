package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.2.0"
	GitCommit = "HEAD"
	BuildDate = "2026-09-18"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and system build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mcp-audit v%s (commit: %s, date: %s, runtime: %s/%s)\n",
			Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
