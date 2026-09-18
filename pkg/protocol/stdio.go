package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// StdioClient manages JSON-RPC 2.0 communication over stdio with an MCP server process.
type StdioClient struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stderrBuf *bytes.Buffer

	cancelCtx context.CancelFunc

	nextID    atomic.Int64
	pendingMu sync.RWMutex
	pending   map[int64]chan *JSONRPCResponse

	writeMu   sync.Mutex
	done      chan struct{}
	closeOnce sync.Once

	errMu     sync.RWMutex
	clientErr error
}

// NewStdioClient launches a local process and sets up bidirectional JSON-RPC 2.0 stdio pipes.
func NewStdioClient(ctx context.Context, command string, args []string, env map[string]string) (*StdioClient, error) {
	procCtx, cancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(procCtx, command, args...)

	// Merge current process environment with custom server environment
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		cancel()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrBuf := new(bytes.Buffer)
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		cancel()
		return nil, fmt.Errorf("failed to start process %q: %w", command, err)
	}

	client := &StdioClient{
		cmd:       cmd,
		stdin:     stdin,
		stdout:    stdout,
		stderrBuf: stderrBuf,
		cancelCtx: cancel,
		pending:   make(map[int64]chan *JSONRPCResponse),
		done:      make(chan struct{}),
	}

	// Watchdog goroutine: ensure process is immediately killed if context expires or cancels
	go func() {
		select {
		case <-procCtx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-client.done:
		}
	}()

	// Start background reader loop for non-blocking stream processing
	go client.readLoop()

	return client, nil
}

// readLoop continuously reads newline-delimited JSON messages from the server's stdout.
func (c *StdioClient) readLoop() {
	defer func() {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
		c.drainPending()
	}()

	reader := bufio.NewReader(c.stdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			c.setErr(fmt.Errorf("server stdout closed: %w", err))
			return
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			// Non-JSON-RPC or log line emitted by the server to stdout; skip or ignore
			continue
		}

		if resp.ID != nil {
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

// drainPending notifies all pending requests that the connection has terminated.
func (c *StdioClient) drainPending() {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *StdioClient) setErr(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.clientErr == nil {
		c.clientErr = err
	}
}

func (c *StdioClient) getErr() error {
	c.errMu.RLock()
	defer c.errMu.RUnlock()
	return c.clientErr
}

// Call sends a JSON-RPC 2.0 request and blocks until a response is received or ctx expires.
func (c *StdioClient) Call(ctx context.Context, method string, params any) (*JSONRPCResponse, error) {
	select {
	case <-c.done:
		return nil, fmt.Errorf("client is closed: %w", c.getErr())
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
	payload = append(payload, '\n')

	c.writeMu.Lock()
	_, err = c.stdin.Write(payload)
	c.writeMu.Unlock()
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("failed to write to stdin: %w", err)
	}

	select {
	case <-ctx.Done():
		c.removePending(id)
		return nil, fmt.Errorf("request canceled or timed out: %w", ctx.Err())
	case <-c.done:
		c.removePending(id)
		return nil, fmt.Errorf("connection terminated: %w", c.getErr())
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

// Notify sends a JSON-RPC 2.0 notification (without an ID, expects no response).
func (c *StdioClient) Notify(method string, params any) error {
	select {
	case <-c.done:
		return fmt.Errorf("client is closed: %w", c.getErr())
	default:
	}

	notif := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	payload, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("failed to encode notification: %w", err)
	}
	payload = append(payload, '\n')

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.stdin.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to write notification to stdin: %w", err)
	}
	return nil
}

func (c *StdioClient) removePending(id int64) {
	c.pendingMu.Lock()
	delete(c.pending, id)
	c.pendingMu.Unlock()
}

// Initialize performs the MCP handshake with the server and sends notifications/initialized.
func (c *StdioClient) Initialize(ctx context.Context, clientInfo ClientInfo) (*InitializeResult, error) {
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    map[string]any{},
		ClientInfo:      clientInfo,
	}

	resp, err := c.Call(ctx, "initialize", params)
	if err != nil {
		return nil, fmt.Errorf("handshake 'initialize' failed: %w", err)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize initialize response: %w", err)
	}

	// Model Context Protocol specification requires sending initialized notification after response
	_ = c.Notify("notifications/initialized", map[string]any{})

	return &result, nil
}

// ListTools queries the MCP server for available tools via "tools/list".
func (c *StdioClient) ListTools(ctx context.Context) ([]Tool, error) {
	resp, err := c.Call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("query 'tools/list' failed: %w", err)
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize tools/list response: %w", err)
	}

	return result.Tools, nil
}

// CallTool invokes a specific tool on the MCP server via "tools/call".
func (c *StdioClient) CallTool(ctx context.Context, name string, args map[string]any) (*CallToolResult, error) {
	params := CallToolParams{
		Name:      name,
		Arguments: args,
	}

	resp, err := c.Call(ctx, "tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("tool call '%s' failed: %w", name, err)
	}

	var result CallToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize tools/call response: %w", err)
	}

	return &result, nil
}

// StderrOutput returns any captured standard error output from the server process.
func (c *StdioClient) StderrOutput() string {
	if c.stderrBuf != nil {
		return c.stderrBuf.String()
	}
	return ""
}

// Close gracefully closes the pipes and terminates the server process.
func (c *StdioClient) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.cancelCtx()
		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		if c.stdout != nil {
			_ = c.stdout.Close()
		}

		if c.cmd != nil && c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
			waitDone := make(chan struct{})
			go func() {
				_ = c.cmd.Wait()
				close(waitDone)
			}()
			select {
			case <-waitDone:
			case <-time.After(2 * time.Second):
			}
		}

		select {
		case <-c.done:
		default:
			close(c.done)
		}
	})
	return closeErr
}
