package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SSEClient manages JSON-RPC 2.0 communication over Server-Sent Events (HTTP/SSE) with an MCP server.
type SSEClient struct {
	httpClient  *http.Client
	sseURL      string
	postURL     string
	postURLReady chan struct{}

	cancelCtx context.CancelFunc

	nextID    atomic.Int64
	pendingMu sync.RWMutex
	pending   map[int64]chan *JSONRPCResponse

	done      chan struct{}
	closeOnce sync.Once

	errMu     sync.RWMutex
	clientErr error
}

// NewSSEClient connects to an MCP server via SSE endpoint (GET) and prepares the POST message endpoint.
func NewSSEClient(ctx context.Context, sseURL string) (*SSEClient, error) {
	parsedURL, err := url.Parse(sseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SSE URL %q: %w", sseURL, err)
	}

	reqCtx, cancel := context.WithCancel(ctx)

	client := &SSEClient{
		httpClient: &http.Client{
			Timeout: 0, // SSE connection remains open
		},
		sseURL:       sseURL,
		postURLReady: make(chan struct{}),
		cancelCtx:    cancel,
		pending:      make(map[int64]chan *JSONRPCResponse),
		done:         make(chan struct{}),
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, sseURL, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to SSE stream at %s: %w", sseURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("server returned non-200 status for SSE: %d %s", resp.StatusCode, resp.Status)
	}

	// Start reading events from the SSE stream in a background goroutine
	go client.readSSELoop(resp, parsedURL)

	// Wait for the endpoint event with a short timeout
	select {
	case <-client.postURLReady:
		return client, nil
	case <-ctx.Done():
		client.Close()
		return nil, fmt.Errorf("timed out waiting for MCP endpoint event: %w", ctx.Err())
	case <-client.done:
		client.Close()
		return nil, fmt.Errorf("SSE connection closed before receiving endpoint: %w", client.getErr())
	}
}

func (c *SSEClient) readSSELoop(resp *http.Response, baseSSEURL *url.URL) {
	defer func() {
		resp.Body.Close()
		select {
		case <-c.done:
		default:
			close(c.done)
		}
		c.drainPending()
	}()

	scanner := bufio.NewScanner(resp.Body)
	// Allow large tokens (up to 10MB) for big tool schemas
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	var currentEvent string
	var currentData strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line marks end of SSE event block
			if currentData.Len() > 0 {
				c.handleSSEEvent(currentEvent, currentData.String(), baseSSEURL)
			}
			currentEvent = ""
			currentData.Reset()
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if currentData.Len() > 0 {
				currentData.WriteString("\n")
			}
			currentData.WriteString(dataContent)
		}
	}

	if err := scanner.Err(); err != nil {
		c.setErr(fmt.Errorf("error reading SSE stream: %w", err))
	}
}

func (c *SSEClient) handleSSEEvent(eventType, data string, baseSSEURL *url.URL) {
	switch eventType {
	case "endpoint":
		targetURL := strings.TrimSpace(data)
		resolved, err := baseSSEURL.Parse(targetURL)
		if err == nil {
			c.postURL = resolved.String()
		} else {
			c.postURL = targetURL
		}
		select {
		case <-c.postURLReady:
		default:
			close(c.postURLReady)
		}

	case "message", "":
		var resp JSONRPCResponse
		if err := json.Unmarshal([]byte(data), &resp); err == nil && resp.ID != nil {
			c.pendingMu.Lock()
			ch, ok := c.pending[*resp.ID]
			if ok {
				delete(c.pending, *resp.ID)
			}
			c.pendingMu.Unlock()

			if ok {
				ch <- &resp
			}
		}
	}
}

func (c *SSEClient) setErr(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.clientErr == nil {
		c.clientErr = err
	}
}

func (c *SSEClient) getErr() error {
	c.errMu.RLock()
	defer c.errMu.RUnlock()
	return c.clientErr
}

func (c *SSEClient) drainPending() {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *SSEClient) removePending(id int64) {
	c.pendingMu.Lock()
	delete(c.pending, id)
	c.pendingMu.Unlock()
}

// Call sends a JSON-RPC 2.0 request via POST to the MCP endpoint and waits for response via SSE.
func (c *SSEClient) Call(ctx context.Context, method string, params any) (*JSONRPCResponse, error) {
	select {
	case <-c.done:
		return nil, fmt.Errorf("SSE client is closed: %w", c.getErr())
	default:
	}

	id := c.nextID.Add(1)
	respChan := make(chan *JSONRPCResponse, 1)

	c.pendingMu.Lock()
	c.pending[id] = respChan
	c.pendingMu.Unlock()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.postURL, bytes.NewReader(payload))
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	postClient := &http.Client{Timeout: 10 * time.Second}
	postResp, err := postClient.Do(httpReq)
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("failed to send POST request: %w", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK && postResp.StatusCode != http.StatusAccepted {
		c.removePending(id)
		return nil, fmt.Errorf("server responded with status %d for POST request", postResp.StatusCode)
	}

	// Some servers return the JSON-RPC response immediately in POST response body instead of SSE stream
	var inlineResp JSONRPCResponse
	if postResp.ContentLength > 0 && postResp.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(postResp.Body).Decode(&inlineResp); err == nil && inlineResp.ID != nil && *inlineResp.ID == id {
			c.removePending(id)
			if inlineResp.Error != nil {
				return nil, inlineResp.Error
			}
			return &inlineResp, nil
		}
	}

	select {
	case <-ctx.Done():
		c.removePending(id)
		return nil, fmt.Errorf("request timed out or canceled: %w", ctx.Err())
	case <-c.done:
		c.removePending(id)
		return nil, fmt.Errorf("SSE connection terminated: %w", c.getErr())
	case resp, ok := <-respChan:
		if !ok || resp == nil {
			return nil, errors.New("connection closed before response received")
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp, nil
	}
}

// Initialize performs the MCP handshake over SSE.
func (c *SSEClient) Initialize(ctx context.Context, clientInfo ClientInfo) (*InitializeResult, error) {
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    map[string]any{},
		ClientInfo:      clientInfo,
	}

	resp, err := c.Call(ctx, "initialize", params)
	if err != nil {
		return nil, fmt.Errorf("SSE initialize failed: %w", err)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize initialize response: %w", err)
	}

	return &result, nil
}

// ListTools retrieves tools over SSE.
func (c *SSEClient) ListTools(ctx context.Context) ([]Tool, error) {
	resp, err := c.Call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("SSE tools/list failed: %w", err)
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize tools/list response: %w", err)
	}

	return result.Tools, nil
}

// CallTool invokes a specific tool on the remote MCP server via "tools/call".
func (c *SSEClient) CallTool(ctx context.Context, name string, args map[string]any) (*CallToolResult, error) {
	params := CallToolParams{
		Name:      name,
		Arguments: args,
	}

	resp, err := c.Call(ctx, "tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("SSE tool call '%s' failed: %w", name, err)
	}

	var result CallToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize tools/call response: %w", err)
	}

	return &result, nil
}

// Close terminates the SSE connection.
func (c *SSEClient) Close() error {
	c.closeOnce.Do(func() {
		c.cancelCtx()
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	})
	return nil
}
