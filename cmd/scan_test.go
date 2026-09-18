package cmd

import (
	"reflect"
	"testing"
)

func TestParseCommandLine(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    `npx -y @modelcontextprotocol/server-filesystem /tmp`,
			expected: []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
		},
		{
			input:    `python -m server --db "test db.sqlite" --flag`,
			expected: []string{"python", "-m", "server", "--db", "test db.sqlite", "--flag"},
		},
		{
			input:    `"./path with spaces/bin" 'arg 1' arg2`,
			expected: []string{"./path with spaces/bin", "arg 1", "arg2"},
		},
	}

	for _, tc := range tests {
		got := parseCommandLine(tc.input)
		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("parseCommandLine(%q) = %v; want %v", tc.input, got, tc.expected)
		}
	}
}

func TestFormatDescription(t *testing.T) {
	singleLine := "Simple tool description"
	if got := formatDescription(singleLine); got != singleLine {
		t.Errorf("expected %q, got %q", singleLine, got)
	}

	multiLine := "First line\nSecond line\nThird line"
	expected := "First line \033[2m(more...)\033[0m"
	if got := formatDescription(multiLine); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
