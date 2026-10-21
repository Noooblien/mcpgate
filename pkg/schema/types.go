package schema

import (
	"time"
)

// PropertyType designates allowable JSON Schema primitive types.
type PropertyType string

const (
	TypeString  PropertyType = "string"
	TypeInteger PropertyType = "integer"
	TypeNumber  PropertyType = "number"
	TypeBoolean PropertyType = "boolean"
	TypeArray   PropertyType = "array"
	TypeObject  PropertyType = "object"
)

// PropertySchema defines parameter constraints for a single tool argument.
type PropertySchema struct {
	Type        PropertyType `json:"type"`
	Description string       `json:"description,omitempty"`
	Enum        []string     `json:"enum,omitempty"`
	Pattern     string       `json:"pattern,omitempty"` // Regex pattern constraint
	MinLength   *int         `json:"minLength,omitempty"`
	MaxLength   *int         `json:"maxLength,omitempty"`
	Minimum     *float64     `json:"minimum,omitempty"`
	Maximum     *float64     `json:"maximum,omitempty"`
}

// ToolInputSchema mirrors the standard MCP Tool inputSchema specification.
type ToolInputSchema struct {
	Type                 PropertyType              `json:"type"` // Must be "object"
	Properties           map[string]PropertySchema `json:"properties"`
	Required             []string                  `json:"required,omitempty"`
	AdditionalProperties bool                      `json:"additionalProperties"` // Reject unexpected args if false
}

// ToolDefinition registers an MCP tool and its strict input validation schema.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema ToolInputSchema `json:"inputSchema"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ValidationErrorDetails details a single argument schema non-compliance.
type ValidationErrorDetails struct {
	Field       string `json:"field"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Value       string `json:"value,omitempty"`
}

// SchemaValidationResult encapsulates the verdict of schema validation.
type SchemaValidationResult struct {
	Valid          bool                     `json:"valid"`
	ToolName       string                   `json:"tool_name"`
	Errors         []ValidationErrorDetails `json:"errors,omitempty"`
	NormalizedArgs map[string]interface{}   `json:"normalized_args"`
	DurationUs     int64                    `json:"duration_us"`
}
