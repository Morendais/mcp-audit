package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// JSON-RPC 2.0 Types

// JSONRPCRequest represents an outgoing JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// JSONRPCNotification represents a one-way notification without an ID.
type JSONRPCNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// JSONRPCResponse represents an incoming JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError defines the standard JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("JSON-RPC error (code %d): %s (data: %s)", e.Code, e.Message, string(e.Data))
	}
	return fmt.Sprintf("JSON-RPC error (code %d): %s", e.Code, e.Message)
}

// MCP Protocol Types

// ClientInfo represents information about the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerInfo represents information about the connected MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeParams holds parameters sent during the MCP handshake.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
}

// InitializeResult holds the server response to the initialize request.
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

// PropertyDef describes a single property in a Tool's input schema, supporting nested objects.
type PropertyDef struct {
	Type        any                    `json:"type,omitempty"`
	Description string                 `json:"description,omitempty"`
	Enum        []any                  `json:"enum,omitempty"`
	Default     any                    `json:"default,omitempty"`
	Properties  map[string]PropertyDef `json:"properties,omitempty"`
	Required    []string               `json:"required,omitempty"`
}

// TypeString returns a clean string representation of the property type.
func (p PropertyDef) TypeString() string {
	switch v := p.Type.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, "|")
	default:
		if v != nil {
			return fmt.Sprint(v)
		}
		return "any"
	}
}

// InputSchema holds the JSON Schema definition for a tool's arguments.
type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]PropertyDef `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
	Raw        json.RawMessage        `json:"-"`
}

// UnmarshalJSON preserves the raw JSON while deserializing standard schema fields.
func (s *InputSchema) UnmarshalJSON(data []byte) error {
	s.Raw = append([]byte(nil), data...)
	type Alias InputSchema
	var aux Alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.Type = aux.Type
	s.Properties = aux.Properties
	s.Required = aux.Required
	return nil
}

// Tool describes an action or capability exposed by an MCP server.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema InputSchema `json:"inputSchema"`
}

// ListToolsResult represents the result returned by the "tools/list" method.
type ListToolsResult struct {
	Tools      []Tool  `json:"tools"`
	NextCursor *string `json:"nextCursor,omitempty"`
}

// CallToolParams represents parameters sent in a "tools/call" request.
type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolContent represents a single content item returned by a tool call.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// CallToolResult represents the response from a "tools/call" request.
type CallToolResult struct {
	Content []ToolContent `json:"content,omitempty"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolCaller is an interface for sending tool execution requests.
type ToolCaller interface {
	CallTool(ctx context.Context, name string, args map[string]any) (*CallToolResult, error)
}

