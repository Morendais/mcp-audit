package config

// ServerConfig holds the execution parameters for a single MCP server.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// ClaudeConfig represents the structure of Claude Desktop configuration file.
type ClaudeConfig struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
}
