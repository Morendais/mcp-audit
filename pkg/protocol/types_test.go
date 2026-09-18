package protocol

import (
	"encoding/json"
	"testing"
)

func TestInputSchema_Unmarshal(t *testing.T) {
	rawSchema := `{
		"type": "object",
		"properties": {
			"query": {
				"type": "string",
				"description": "SQL query to execute"
			},
			"limit": {
				"type": "integer",
				"description": "Maximum number of rows",
				"default": 10
			},
			"mode": {
				"type": "string",
				"enum": ["read_only", "read_write"]
			}
		},
		"required": ["query"]
	}`

	var schema InputSchema
	if err := json.Unmarshal([]byte(rawSchema), &schema); err != nil {
		t.Fatalf("failed to unmarshal InputSchema: %v", err)
	}

	if schema.Type != "object" {
		t.Fatalf("expected type 'object', got %q", schema.Type)
	}

	if len(schema.Required) != 1 || schema.Required[0] != "query" {
		t.Fatalf("unexpected required fields: %v", schema.Required)
	}

	if len(schema.Properties) != 3 {
		t.Fatalf("expected 3 properties, got %d", len(schema.Properties))
	}

	queryProp, ok := schema.Properties["query"]
	if !ok {
		t.Fatal("property 'query' not found")
	}
	if queryProp.TypeString() != "string" {
		t.Fatalf("expected type 'string', got %s", queryProp.TypeString())
	}

	modeProp, ok := schema.Properties["mode"]
	if !ok {
		t.Fatal("property 'mode' not found")
	}
	if len(modeProp.Enum) != 2 {
		t.Fatalf("expected 2 enum values, got %d", len(modeProp.Enum))
	}

	// Verify raw JSON was preserved
	if len(schema.Raw) == 0 {
		t.Fatal("expected schema.Raw to be populated")
	}
}

func TestJSONRPCError_Formatting(t *testing.T) {
	err := &JSONRPCError{
		Code:    -32601,
		Message: "Method not found",
		Data:    json.RawMessage(`"extra details"`),
	}

	str := err.Error()
	if str != `JSON-RPC error (code -32601): Method not found (data: "extra details")` {
		t.Fatalf("unexpected error format: %s", str)
	}
}
