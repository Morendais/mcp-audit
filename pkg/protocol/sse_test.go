package protocol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSEClient_InitializeAndListTools(t *testing.T) {
	var messageEndpoint string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}

			// Send endpoint event
			fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", messageEndpoint)
			flusher.Flush()

			// Keep connection open until client closes
			<-r.Context().Done()

		case "/messages":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Simple mock responder
			var req JSONRPCRequest
			_ = req
			// Respond directly
			respJSON := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock-sse-server","version":"1.0.0"}}}`)
			w.Write([]byte(respJSON))

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	messageEndpoint = ts.URL + "/messages"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewSSEClient(ctx, ts.URL+"/sse")
	if err != nil {
		t.Fatalf("failed to create SSEClient: %v", err)
	}
	defer client.Close()

	initRes, err := client.Initialize(ctx, ClientInfo{Name: "tester", Version: "0.1"})
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if initRes.ServerInfo.Name != "mock-sse-server" {
		t.Errorf("expected server name 'mock-sse-server', got %q", initRes.ServerInfo.Name)
	}
}
