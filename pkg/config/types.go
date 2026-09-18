package config

// ServerConfig holds the execution parameters for a single MCP server.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// ClaudeConfig represents the structure of Claude Desktop / Cursor / Windsurf configuration files.
type ClaudeConfig struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
}

// DiscoveredServer represents an MCP server found during auto-discovery.
type DiscoveredServer struct {
	Name       string       `json:"name"`
	Source     string       `json:"source"`
	ConfigPath string       `json:"config_path"`
	Config     ServerConfig `json:"config"`
}
