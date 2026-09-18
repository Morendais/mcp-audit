package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestHelperProcess serves as an echo MCP mock server for testing StdioClient.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		switch req.Method {
		case "initialize":
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock-server","version":"0.9.0"},"instructions":"test instructions"}}`+"\n", req.ID)
			os.Stdout.WriteString(resp)

		case "tools/list":
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"ping","description":"Check connectivity","inputSchema":{"type":"object","properties":{"host":{"type":"string","description":"Host to ping"}},"required":["host"]}}]}}`+"\n", req.ID)
			os.Stdout.WriteString(resp)
		}
	}
	os.Exit(0)
}

func TestStdioClient_InitializeAndListTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewStdioClient(
		ctx,
		os.Args[0],
		[]string{"-test.run=TestHelperProcess", "--"},
		map[string]string{"GO_WANT_HELPER_PROCESS": "1"},
	)
	if err != nil {
		t.Fatalf("failed to create StdioClient: %v", err)
	}
	defer client.Close()

	// Handshake
	clientInfo := ClientInfo{Name: "mcp-audit-test", Version: "0.1.0"}
	initRes, err := client.Initialize(ctx, clientInfo)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if initRes.ServerInfo.Name != "mock-server" {
		t.Errorf("expected server name 'mock-server', got %q", initRes.ServerInfo.Name)
	}
	if initRes.ServerInfo.Version != "0.9.0" {
		t.Errorf("expected server version '0.9.0', got %q", initRes.ServerInfo.Version)
	}

	// Tools list
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	if tools[0].Name != "ping" {
		t.Errorf("expected tool name 'ping', got %q", tools[0].Name)
	}

	hostProp, ok := tools[0].InputSchema.Properties["host"]
	if !ok {
		t.Fatal("expected property 'host' in inputSchema")
	}
	if hostProp.TypeString() != "string" {
		t.Errorf("expected host type 'string', got %s", hostProp.TypeString())
	}
}

func TestStdioClient_Timeout(t *testing.T) {
	// Create a client running a command that does not respond to JSON-RPC
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := NewStdioClient(
		ctx,
		os.Args[0],
		[]string{"-test.run=TestHelperProcess", "--"},
		nil, // GO_WANT_HELPER_PROCESS is not set, so helper process exits or does not reply
	)
	if err != nil {
		t.Fatalf("failed to create StdioClient: %v", err)
	}
	defer client.Close()

	// Short timeout call
	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()

	_, err = client.Initialize(callCtx, ClientInfo{Name: "test", Version: "1.0"})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
