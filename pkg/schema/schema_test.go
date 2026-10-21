package schema

import (
	"testing"
)

func TestSchemaRegistry_BasicValidation(t *testing.T) {
	reg := NewSchemaRegistry(true)

	// Valid read_file
	v1 := reg.ValidateArguments("read_file", map[string]interface{}{"path": "app.go"})
	if !v1.Valid {
		t.Fatalf("expected valid read_file call, got errors: %+v", v1.Errors)
	}

	// Missing required "path"
	v2 := reg.ValidateArguments("read_file", map[string]interface{}{})
	if v2.Valid {
		t.Fatalf("expected missing required path to fail validation")
	}

	// Unexpected argument with AdditionalProperties=false
	v3 := reg.ValidateArguments("read_file", map[string]interface{}{
		"path":   "app.go",
		"rogue": "exploit",
	})
	if v3.Valid {
		t.Fatalf("expected unexpected argument to fail validation")
	}

	// Unregistered tool in strict mode
	v4 := reg.ValidateArguments("unknown_tool", map[string]interface{}{})
	if v4.Valid {
		t.Fatalf("expected unregistered tool to fail in strict mode")
	}
}

func TestSchemaRegistry_ConstraintsAndTypes(t *testing.T) {
	reg := NewSchemaRegistry(false)

	minVal := 10.0
	maxVal := 100.0
	_ = reg.RegisterTool(ToolDefinition{
		Name: "configure_server",
		InputSchema: ToolInputSchema{
			Type: TypeObject,
			Properties: map[string]PropertySchema{
				"port": {
					Type:    TypeInteger,
					Minimum: &minVal,
					Maximum: &maxVal,
				},
				"mode": {
					Type: TypeString,
					Enum: []string{"debug", "production"},
				},
				"host": {
					Type:    TypeString,
					Pattern: `^[a-z]+\.[a-z]+$`,
				},
			},
			Required:             []string{"port", "mode"},
			AdditionalProperties: false,
		},
	})

	// Valid
	vOk := reg.ValidateArguments("configure_server", map[string]interface{}{
		"port": 80,
		"mode": "production",
		"host": "example.com",
	})
	if !vOk.Valid {
		t.Fatalf("expected valid configure_server call, got errors: %+v", vOk.Errors)
	}

	// Range violation
	vRange := reg.ValidateArguments("configure_server", map[string]interface{}{
		"port": 5, // < 10
		"mode": "production",
	})
	if vRange.Valid {
		t.Fatalf("expected out-of-range port to fail")
	}

	// Enum violation
	vEnum := reg.ValidateArguments("configure_server", map[string]interface{}{
		"port": 80,
		"mode": "unsupported_mode",
	})
	if vEnum.Valid {
		t.Fatalf("expected invalid enum mode to fail")
	}

	// Pattern violation
	vPattern := reg.ValidateArguments("configure_server", map[string]interface{}{
		"port": 80,
		"mode": "debug",
		"host": "192.168.1.1:8080", // Doesn't match ^[a-z]+\.[a-z]+$
	})
	if vPattern.Valid {
		t.Fatalf("expected regex pattern mismatch to fail")
	}
}

func TestSchema_DemoAndScorecard(t *testing.T) {
	summary := RunSchemaDemo()
	if summary.TotalValidated != 6 {
		t.Fatalf("expected 6 evaluated test cases, got %d", summary.TotalValidated)
	}
	if summary.ValidCount != 2 || summary.InvalidCount != 4 {
		t.Fatalf("expected 2 valid, 4 invalid, got valid=%d, invalid=%d", summary.ValidCount, summary.InvalidCount)
	}

	scorecard := RenderSchemaScorecard(summary)
	if len(scorecard) == 0 {
		t.Fatalf("expected non-empty ANSI scorecard")
	}

	markdown := RenderSchemaMarkdown(summary)
	if len(markdown) == 0 {
		t.Fatalf("expected non-empty Markdown report")
	}

	mermaid := RenderSchemaMermaid(summary.Evaluations)
	if len(mermaid) == 0 {
		t.Fatalf("expected non-empty Mermaid diagram")
	}
}
