package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"mcp-audit/pkg/audit"
	"mcp-audit/pkg/config"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func runRootDefault(cmd *cobra.Command, args []string) error {
	// If direct execution or config flags were provided, run standard scan
	if execCmdFlag != "" || configPathFlag != "" {
		return runScan(cmd, args)
	}

	return runInteractiveTUI()
}

func runInteractiveTUI() error {
	fmt.Println()
	fmt.Println("\033[1;36m╔═══════════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;37m║                     mcp-audit — Zero-Config Security Auditor                     ║\033[0m")
	fmt.Println("\033[1;36m╚═══════════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	servers, candidateLocations, err := config.DiscoverAllServers()
	if err != nil {
		return fmt.Errorf("discovery error: %w", err)
	}

	if len(servers) == 0 {
		fmt.Println("\033[1;33m[!] No active MCP server configurations detected.\033[0m")
		fmt.Println("\033[2mChecked standard locations:\033[0m")
		for _, loc := range candidateLocations {
			fmt.Printf("    - %s: %s\n", loc.Name, loc.Path)
		}
		fmt.Println()
		fmt.Println("\033[1;37mQuick start options to audit an MCP server:\033[0m")
		fmt.Println("  1. Audit any server command directly:")
		fmt.Println("     \033[1;32mmcp-audit scan --exec \"npx -y @modelcontextprotocol/server-filesystem /tmp\"\033[0m")
		fmt.Println()
		fmt.Println("  2. Audit a remote SSE server:")
		fmt.Println("     \033[1;32mmcp-audit remote --sse http://localhost:8000/sse\033[0m")
		fmt.Println()
		fmt.Println("  3. Specify a configuration file explicitly:")
		fmt.Println("     \033[1;32mmcp-audit scan --config ./claude_desktop_config.json\033[0m")
		fmt.Println()
		return nil
	}

	sourcesCount := make(map[string]int)
	for _, s := range servers {
		sourcesCount[s.Source]++
	}
	var sourceLabels []string
	for src := range sourcesCount {
		sourceLabels = append(sourceLabels, src)
	}
	sourcesStr := strings.Join(sourceLabels, ", ")

	fmt.Printf("\033[1;34m[+] Discovered %d MCP server(s) in %s:\033[0m\n\n", len(servers), sourcesStr)

	// Check if terminal is interactive
	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))
	var selected []config.DiscoveredServer

	if !isTerminal {
		fmt.Printf("\033[2m[i] Non-interactive environment detected. Auditing all %d discovered servers...\033[0m\n", len(servers))
		selected = servers
	} else {
		chosen, err := promptSelectServers(servers)
		if err != nil {
			return err
		}
		selected = chosen
	}

	if len(selected) == 0 {
		fmt.Println("\033[33mNo servers selected for audit. Exiting.\033[0m")
		return nil
	}

	fmt.Println()
	fmt.Printf("\033[1;32m> Starting express audit for %d server(s)...\033[0m\n\n", len(selected))

	var cards []audit.ServerScorecard
	for idx, s := range selected {
		cmdDisplay := s.Config.Command + " " + strings.Join(s.Config.Args, " ")
		if len(cmdDisplay) > 60 {
			cmdDisplay = cmdDisplay[:57] + "..."
		}
		fmt.Printf("  \033[1;36m[%d/%d]\033[0m Auditing \033[1m%s\033[0m (\033[2m%s\033[0m)...\n", idx+1, len(selected), s.Name, cmdDisplay)

		tools, findings, auditErr := auditServer(s.Name, s.Config, false, true, true)
		sc := audit.EvaluateServerScorecard(s.Name, s.Source, cmdDisplay, len(tools), findings, auditErr)
		cards = append(cards, sc)

		switch sc.Status {
		case audit.StatusGreen:
			fmt.Printf("        \033[32m✔ %s\033[0m\n", sc.Headline)
		case audit.StatusRed:
			fmt.Printf("        \033[1;31m✖ %s\033[0m\n", sc.Headline)
		case audit.StatusYellow:
			fmt.Printf("        \033[33m▲ %s\033[0m\n", sc.Headline)
		default:
			fmt.Printf("        \033[90m○ %s\033[0m\n", sc.Headline)
		}
		time.Sleep(100 * time.Millisecond)
	}

	scorecardOut := audit.FormatScorecard(cards)
	fmt.Print(scorecardOut)

	return nil
}

func promptSelectServers(servers []config.DiscoveredServer) ([]config.DiscoveredServer, error) {
	checked := make([]bool, len(servers))
	for i := range checked {
		checked[i] = true
	}

	cursor := 0
	fd := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fallbackLinePrompt(servers, checked)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
		fmt.Print("\033[?25h")
	}()

	fmt.Print("\033[?25l")

	linesCount := len(servers) + 2
	firstRender := true

	for {
		if !firstRender {
			fmt.Printf("\033[%dA", linesCount)
		}
		firstRender = false

		for i, s := range servers {
			cursorMark := "  "
			if i == cursor {
				cursorMark = "\033[1;36m> \033[0m"
			}

			checkMark := "\033[2m[ ]\033[0m"
			if checked[i] {
				checkMark = "\033[1;32m[x]\033[0m"
			}

			cmdStr := s.Config.Command + " " + strings.Join(s.Config.Args, " ")
			if len(cmdStr) > 50 {
				cmdStr = cmdStr[:47] + "..."
			}

			fmt.Printf("\r\033[K%s%s \033[1m%-20s\033[0m \033[2m(%s)\033[0m\n",
				cursorMark, checkMark, s.Name, cmdStr)
		}

		fmt.Println("\r\033[K")
		fmt.Printf("\r\033[K\033[2mControls: [↑/↓] Navigate  [Space] Toggle  [a] Toggle All  [Enter] Start Audit  [q] Quit\033[0m\n")

		var buf [3]byte
		n, readErr := os.Stdin.Read(buf[:])
		if readErr != nil {
			break
		}

		if n == 1 {
			switch buf[0] {
			case 3:
				return nil, fmt.Errorf("audit cancelled by user")
			case 13, 10:
				goto done
			case ' ':
				checked[cursor] = !checked[cursor]
			case 'a', 'A':
				allChecked := true
				for _, c := range checked {
					if !c {
						allChecked = false
						break
					}
				}
				for i := range checked {
					checked[i] = !allChecked
				}
			case 'k', 'K':
				if cursor > 0 {
					cursor--
				} else {
					cursor = len(servers) - 1
				}
			case 'j', 'J':
				if cursor < len(servers)-1 {
					cursor++
				} else {
					cursor = 0
				}
			case 'q', 'Q':
				return nil, fmt.Errorf("audit cancelled by user")
			default:
				if buf[0] >= '1' && int(buf[0]-'1') < len(servers) {
					idx := int(buf[0] - '1')
					checked[idx] = !checked[idx]
				}
			}
		} else if n >= 3 && buf[0] == 27 && buf[1] == '[' {
			switch buf[2] {
			case 'A':
				if cursor > 0 {
					cursor--
				} else {
					cursor = len(servers) - 1
				}
			case 'B':
				if cursor < len(servers)-1 {
					cursor++
				} else {
					cursor = 0
				}
			}
		}
	}

done:
	var result []config.DiscoveredServer
	for i, s := range servers {
		if checked[i] {
			result = append(result, s)
		}
	}
	return result, nil
}

func fallbackLinePrompt(servers []config.DiscoveredServer, checked []bool) ([]config.DiscoveredServer, error) {
	reader := bufio.NewReader(os.Stdin)
	for i, s := range servers {
		cmdStr := s.Config.Command + " " + strings.Join(s.Config.Args, " ")
		fmt.Printf("[%d] %s (%s)\n", i+1, s.Name, cmdStr)
	}
	fmt.Print("\nPress [Enter] to audit all, or enter comma-separated numbers (e.g. 1,2): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return servers, nil
	}

	var result []config.DiscoveredServer
	parts := strings.Split(input, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var num int
		if _, err := fmt.Sscanf(p, "%d", &num); err == nil && num >= 1 && num <= len(servers) {
			result = append(result, servers[num-1])
		}
	}
	return result, nil
}
