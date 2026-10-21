package schema

import (
	"fmt"
	"regexp"
	"sync"
	"time"
)

// SchemaRegistry stores and validates input schemas for all registered MCP tools.
type SchemaRegistry struct {
	mu             sync.RWMutex
	tools          map[string]ToolDefinition
	regexCache     map[string]*regexp.Regexp
	strictUnknowns bool
}

// NewSchemaRegistry constructs a thread-safe tool schema validation registry.
func NewSchemaRegistry(strictUnknowns bool) *SchemaRegistry {
	reg := &SchemaRegistry{
		tools:          make(map[string]ToolDefinition),
		regexCache:     make(map[string]*regexp.Regexp),
		strictUnknowns: strictUnknowns,
	}
	reg.registerDefaultBuiltins()
	return reg
}

// RegisterTool adds or updates a tool definition and its argument schema.
func (r *SchemaRegistry) RegisterTool(tool ToolDefinition) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tool.Name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}
	if tool.InputSchema.Type == "" {
		tool.InputSchema.Type = TypeObject
	}

	// Pre-compile property regexes if provided
	for propName, prop := range tool.InputSchema.Properties {
		if prop.Pattern != "" {
			compiled, err := regexp.Compile(prop.Pattern)
			if err != nil {
				return fmt.Errorf("invalid pattern regex for property '%s': %w", propName, err)
			}
			r.regexCache[prop.Pattern] = compiled
		}
	}

	tool.UpdatedAt = time.Now().UTC()
	r.tools[tool.Name] = tool
	return nil
}

// GetTool retrieves a tool definition by name.
func (r *SchemaRegistry) GetTool(name string) (ToolDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// ListTools returns all registered tools.
func (r *SchemaRegistry) ListTools() []ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]ToolDefinition, 0, len(r.tools))
	for _, t := range r.tools {
		list = append(list, t)
	}
	return list
}

// ValidateArguments enforces type, required fields, constraints, and unknown argument rules.
func (r *SchemaRegistry) ValidateArguments(toolName string, args map[string]interface{}) SchemaValidationResult {
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()

	tool, exists := r.tools[toolName]
	if !exists {
		// If tool is uncatalogued, check if strict unknown mode is on
		if r.strictUnknowns {
			return SchemaValidationResult{
				Valid:    false,
				ToolName: toolName,
				Errors: []ValidationErrorDetails{
					{
						Field:       "tool",
						Rule:        "unregistered_tool",
						Description: fmt.Sprintf("tool '%s' is not registered in schema validator", toolName),
					},
				},
				NormalizedArgs: args,
				DurationUs:     time.Since(start).Microseconds(),
			}
		}
		// In permissive mode, uncatalogued tools pass schema validation
		return SchemaValidationResult{
			Valid:          true,
			ToolName:       toolName,
			NormalizedArgs: args,
			DurationUs:     time.Since(start).Microseconds(),
		}
	}

	if args == nil {
		args = make(map[string]interface{})
	}

	var errors []ValidationErrorDetails
	schema := tool.InputSchema

	// 1. Check required parameters
	for _, req := range schema.Required {
		if _, present := args[req]; !present {
			errors = append(errors, ValidationErrorDetails{
				Field:       req,
				Rule:        "required",
				Description: fmt.Sprintf("missing required argument '%s'", req),
			})
		}
	}

	// 2. Check additional unexpected properties
	if !schema.AdditionalProperties {
		for key, val := range args {
			if _, defined := schema.Properties[key]; !defined {
				errors = append(errors, ValidationErrorDetails{
					Field:       key,
					Rule:        "unexpected_property",
					Description: fmt.Sprintf("unknown argument '%s' not allowed by tool schema", key),
					Value:       fmt.Sprintf("%v", val),
				})
			}
		}
	}

	// 3. Check property type, pattern, enum, and range constraints
	for propName, prop := range schema.Properties {
		val, exists := args[propName]
		if !exists || val == nil {
			continue
		}

		errs := r.validateProperty(propName, prop, val)
		errors = append(errors, errs...)
	}

	return SchemaValidationResult{
		Valid:          len(errors) == 0,
		ToolName:       toolName,
		Errors:         errors,
		NormalizedArgs: args,
		DurationUs:     time.Since(start).Microseconds(),
	}
}

func (r *SchemaRegistry) validateProperty(name string, prop PropertySchema, val interface{}) []ValidationErrorDetails {
	var errs []ValidationErrorDetails
	valStr := fmt.Sprintf("%v", val)

	switch prop.Type {
	case TypeString:
		s, ok := val.(string)
		if !ok {
			return []ValidationErrorDetails{{
				Field:       name,
				Rule:        "type_mismatch",
				Description: fmt.Sprintf("argument '%s' must be string, got %T", name, val),
				Value:       valStr,
			}}
		}
		if prop.MinLength != nil && len(s) < *prop.MinLength {
			errs = append(errs, ValidationErrorDetails{
				Field:       name,
				Rule:        "minLength",
				Description: fmt.Sprintf("argument '%s' length (%d) is shorter than minLength %d", name, len(s), *prop.MinLength),
				Value:       s,
			})
		}
		if prop.MaxLength != nil && len(s) > *prop.MaxLength {
			errs = append(errs, ValidationErrorDetails{
				Field:       name,
				Rule:        "maxLength",
				Description: fmt.Sprintf("argument '%s' length (%d) exceeds maxLength %d", name, len(s), *prop.MaxLength),
				Value:       s,
			})
		}
		if prop.Pattern != "" {
			rx, ok := r.regexCache[prop.Pattern]
			if !ok {
				rx, _ = regexp.Compile(prop.Pattern)
			}
			if rx != nil && !rx.MatchString(s) {
				errs = append(errs, ValidationErrorDetails{
					Field:       name,
					Rule:        "pattern_mismatch",
					Description: fmt.Sprintf("argument '%s' does not match pattern '%s'", name, prop.Pattern),
					Value:       s,
				})
			}
		}
		if len(prop.Enum) > 0 {
			matched := false
			for _, allowed := range prop.Enum {
				if s == allowed {
					matched = true
					break
				}
			}
			if !matched {
				errs = append(errs, ValidationErrorDetails{
					Field:       name,
					Rule:        "enum_mismatch",
					Description: fmt.Sprintf("argument '%s' value '%s' is not in allowed enum options %v", name, s, prop.Enum),
					Value:       s,
				})
			}
		}

	case TypeInteger, TypeNumber:
		var num float64
		switch v := val.(type) {
		case int:
			num = float64(v)
		case int64:
			num = float64(v)
		case float64:
			num = v
			if prop.Type == TypeInteger && num != float64(int64(num)) {
				return []ValidationErrorDetails{{
					Field:       name,
					Rule:        "type_mismatch",
					Description: fmt.Sprintf("argument '%s' must be an integer, got float %v", name, num),
					Value:       valStr,
				}}
			}
		default:
			return []ValidationErrorDetails{{
				Field:       name,
				Rule:        "type_mismatch",
				Description: fmt.Sprintf("argument '%s' must be numeric, got %T", name, val),
				Value:       valStr,
			}}
		}

		if prop.Minimum != nil && num < *prop.Minimum {
			errs = append(errs, ValidationErrorDetails{
				Field:       name,
				Rule:        "minimum",
				Description: fmt.Sprintf("argument '%s' value %v is less than minimum %v", name, num, *prop.Minimum),
				Value:       valStr,
			})
		}
		if prop.Maximum != nil && num > *prop.Maximum {
			errs = append(errs, ValidationErrorDetails{
				Field:       name,
				Rule:        "maximum",
				Description: fmt.Sprintf("argument '%s' value %v is greater than maximum %v", name, num, *prop.Maximum),
				Value:       valStr,
			})
		}

	case TypeBoolean:
		if _, ok := val.(bool); !ok {
			return []ValidationErrorDetails{{
				Field:       name,
				Rule:        "type_mismatch",
				Description: fmt.Sprintf("argument '%s' must be boolean, got %T", name, val),
				Value:       valStr,
			}}
		}

	case TypeArray:
		if _, ok := val.([]interface{}); !ok {
			return []ValidationErrorDetails{{
				Field:       name,
				Rule:        "type_mismatch",
				Description: fmt.Sprintf("argument '%s' must be an array, got %T", name, val),
				Value:       valStr,
			}}
		}

	case TypeObject:
		if _, ok := val.(map[string]interface{}); !ok {
			return []ValidationErrorDetails{{
				Field:       name,
				Rule:        "type_mismatch",
				Description: fmt.Sprintf("argument '%s' must be an object, got %T", name, val),
				Value:       valStr,
			}}
		}
	}

	return errs
}

// registerDefaultBuiltins registers schemas for core MCP standard tools.
func (r *SchemaRegistry) registerDefaultBuiltins() {
	min1 := 1
	max4096 := 4096

	_ = r.RegisterTool(ToolDefinition{
		Name:        "read_file",
		Description: "Read file contents from local filesystem",
		InputSchema: ToolInputSchema{
			Type: TypeObject,
			Properties: map[string]PropertySchema{
				"path": {
					Type:        TypeString,
					Description: "Absolute or relative file path to read",
					MinLength:   &min1,
					MaxLength:   &max4096,
				},
			},
			Required:             []string{"path"},
			AdditionalProperties: false,
		},
	})

	_ = r.RegisterTool(ToolDefinition{
		Name:        "write_file",
		Description: "Write contents to a file on local filesystem",
		InputSchema: ToolInputSchema{
			Type: TypeObject,
			Properties: map[string]PropertySchema{
				"path": {
					Type:        TypeString,
					Description: "Target file path",
					MinLength:   &min1,
				},
				"content": {
					Type:        TypeString,
					Description: "File contents to write",
				},
			},
			Required:             []string{"path", "content"},
			AdditionalProperties: false,
		},
	})

	_ = r.RegisterTool(ToolDefinition{
		Name:        "web_search",
		Description: "Query a web search engine",
		InputSchema: ToolInputSchema{
			Type: TypeObject,
			Properties: map[string]PropertySchema{
				"query": {
					Type:        TypeString,
					Description: "Search query text",
					MinLength:   &min1,
				},
				"max_results": {
					Type:        TypeInteger,
					Description: "Maximum results count",
				},
			},
			Required:             []string{"query"},
			AdditionalProperties: false,
		},
	})
}
