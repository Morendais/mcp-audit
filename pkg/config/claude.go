package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// CandidateLocation describes a known path and source type for MCP configurations.
type CandidateLocation struct {
	Name string
	Path string
}

// GetCandidateConfigPaths returns standard config locations across Claude Desktop, Cursor, and Cline.
func GetCandidateConfigPaths() []CandidateLocation {
	homeDir, _ := os.UserHomeDir()
	var candidates []CandidateLocation

	// 1. Current working directory checks
	candidates = append(candidates,
		CandidateLocation{Name: "Local directory (mcp.json)", Path: "mcp.json"},
		CandidateLocation{Name: "Local Cursor (.cursor/mcp.json)", Path: filepath.Join(".cursor", "mcp.json")},
		CandidateLocation{Name: "Local Cline (cline_mcp_settings.json)", Path: "cline_mcp_settings.json"},
	)

	// 2. User home Cursor config
	if homeDir != "" {
		candidates = append(candidates,
			CandidateLocation{Name: "Cursor Home (~/.cursor/mcp.json)", Path: filepath.Join(homeDir, ".cursor", "mcp.json")},
		)
	}

	// 3. Cline extension settings
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			clinePath := filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
			candidates = append(candidates, CandidateLocation{Name: "Cline VS Code Settings", Path: clinePath})
		}
	case "darwin":
		if homeDir != "" {
			clinePath := filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
			candidates = append(candidates, CandidateLocation{Name: "Cline VS Code Settings", Path: clinePath})
		}
	case "linux":
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" && homeDir != "" {
			xdgConfig = filepath.Join(homeDir, ".config")
		}
		if xdgConfig != "" {
			clinePath := filepath.Join(xdgConfig, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
			candidates = append(candidates, CandidateLocation{Name: "Cline VS Code Settings", Path: clinePath})
		}
	}

	// 4. Windsurf config
	if homeDir != "" {
		candidates = append(candidates,
			CandidateLocation{Name: "Windsurf (~/.codeium/windsurf/mcp_config.json)", Path: filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json")},
		)
	}
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			candidates = append(candidates,
				CandidateLocation{Name: "Windsurf Config", Path: filepath.Join(appData, "Codeium", "Windsurf", "mcp_config.json")},
				CandidateLocation{Name: "Cursor Settings", Path: filepath.Join(appData, "Cursor", "mcp.json")},
			)
		}
	case "darwin":
		if homeDir != "" {
			candidates = append(candidates,
				CandidateLocation{Name: "Windsurf Config", Path: filepath.Join(homeDir, "Library", "Application Support", "Codeium", "Windsurf", "mcp_config.json")},
			)
		}
	case "linux":
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" && homeDir != "" {
			xdgConfig = filepath.Join(homeDir, ".config")
		}
		if xdgConfig != "" {
			candidates = append(candidates,
				CandidateLocation{Name: "Windsurf Config", Path: filepath.Join(xdgConfig, "Codeium", "Windsurf", "mcp_config.json")},
			)
		}
	}

	// 5. Claude Desktop config
	if claudePath, err := DefaultClaudeDesktopConfigPath(); err == nil && claudePath != "" {
		candidates = append(candidates, CandidateLocation{Name: "Claude Desktop", Path: claudePath})
	}

	return candidates
}

// DefaultClaudeDesktopConfigPath returns the standard Claude Desktop configuration path for the current OS.
func DefaultClaudeDesktopConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil && runtime.GOOS != "windows" {
		return "", fmt.Errorf("unable to determine user home directory: %w", err)
	}

	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			if homeDir != "" {
				appData = filepath.Join(homeDir, "AppData", "Roaming")
			} else {
				return "", fmt.Errorf("APPDATA environment variable is not set")
			}
		}
		return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil

	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil

	case "linux":
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(homeDir, ".config")
		}
		return filepath.Join(xdgConfig, "Claude", "claude_desktop_config.json"), nil

	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// AutoDiscoverConfig automatically searches for an existing MCP configuration file.
func AutoDiscoverConfig() (string, string, error) {
	candidates := GetCandidateConfigPaths()
	for _, c := range candidates {
		if fi, err := os.Stat(c.Path); err == nil && !fi.IsDir() {
			return c.Path, c.Name, nil
		}
	}

	var checkedList string
	for _, c := range candidates {
		checkedList += fmt.Sprintf("    - %s: %s\n", c.Name, c.Path)
	}

	return "", "", fmt.Errorf("no MCP configuration file found. Checked locations:\n%s\nTips:\n    - Run direct command scan without config: mcp-audit local --exec \"python3 /path/to/server.py\"\n    - Or create a simple ./mcp.json in the current directory\n    - Or specify path explicitly: --config <path>", checkedList)
}

// FindClaudeDesktopConfig locates the Claude Desktop config file, verifying that it exists.
func FindClaudeDesktopConfig() (string, error) {
	path, _, err := AutoDiscoverConfig()
	return path, err
}

// LoadClaudeConfig reads and parses the JSON configuration from the specified file path.
func LoadClaudeConfig(filePath string) (*ClaudeConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	var cfg ClaudeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %q: %w", filePath, err)
	}

	if cfg.MCPServers == nil {
		cfg.MCPServers = make(map[string]ServerConfig)
	}

	return &cfg, nil
}

// DiscoverAllServers searches all candidate configuration locations and returns all discovered MCP servers.
func DiscoverAllServers() ([]DiscoveredServer, []CandidateLocation, error) {
	candidates := GetCandidateConfigPaths()
	var discovered []DiscoveredServer
	var foundLocations []CandidateLocation
	seen := make(map[string]bool)

	for _, c := range candidates {
		fi, err := os.Stat(c.Path)
		if err != nil || fi.IsDir() {
			continue
		}
		foundLocations = append(foundLocations, c)
		cfg, err := LoadClaudeConfig(c.Path)
		if err != nil {
			continue
		}
		for name, srv := range cfg.MCPServers {
			key := fmt.Sprintf("%s::%s", name, srv.Command)
			if seen[key] {
				continue
			}
			seen[key] = true
			discovered = append(discovered, DiscoveredServer{
				Name:       name,
				Source:     c.Name,
				ConfigPath: c.Path,
				Config:     srv,
			})
		}
	}

	return discovered, candidates, nil
}
