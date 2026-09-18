package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultClaudeDesktopConfigPath(t *testing.T) {
	p, err := DefaultClaudeDesktopConfigPath()
	if err != nil {
		t.Fatalf("DefaultClaudeDesktopConfigPath returned error: %v", err)
	}
	if p == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(p) != "claude_desktop_config.json" {
		t.Fatalf("expected filename claude_desktop_config.json, got %s", filepath.Base(p))
	}
}

func TestLoadClaudeConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "claude_desktop_config.json")

	validJSON := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {
					"DEBUG": "true"
				}
			},
			"github": {
				"command": "docker",
				"args": ["run", "-i", "mcp/github"]
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(validJSON), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadClaudeConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClaudeConfig failed: %v", err)
	}

	if len(cfg.MCPServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.MCPServers))
	}

	fsServer, ok := cfg.MCPServers["filesystem"]
	if !ok {
		t.Fatal("filesystem server not found")
	}
	if fsServer.Command != "npx" {
		t.Fatalf("expected command 'npx', got %q", fsServer.Command)
	}
	if len(fsServer.Args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(fsServer.Args))
	}
	if fsServer.Env["DEBUG"] != "true" {
		t.Fatalf("expected env DEBUG=true, got %v", fsServer.Env["DEBUG"])
	}

	ghServer, ok := cfg.MCPServers["github"]
	if !ok {
		t.Fatal("github server not found")
	}
	if ghServer.Command != "docker" {
		t.Fatalf("expected command 'docker', got %q", ghServer.Command)
	}
}

func TestLoadClaudeConfig_NotFound(t *testing.T) {
	_, err := LoadClaudeConfig("non_existent_file_path_12345.json")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestLoadClaudeConfig_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.json")
	_ = os.WriteFile(configPath, []byte("{invalid json"), 0644)

	_, err := LoadClaudeConfig(configPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
