package schema

import (
	"time"
)

// RunSchemaDemo demonstrates schema validation across compliant, malformed, and adversarial payloads.
func RunSchemaDemo() SchemaSummary {
	start := time.Now()
	reg := NewSchemaRegistry(false)

	// Register a specialized enterprise tool schema
	min1 := 1
	minAmount := 1.0
	maxAmount := 10000.0

	_ = reg.RegisterTool(ToolDefinition{
		Name:        "transfer_funds",
		Description: "Transfer financial tokens to a verified destination account",
		InputSchema: ToolInputSchema{
			Type: TypeObject,
			Properties: map[string]PropertySchema{
				"account_id": {
					Type:      TypeString,
					Pattern:   `^acct_[a-z0-9]{8,16}$`,
					MinLength: &min1,
				},
				"amount": {
					Type:    TypeNumber,
					Minimum: &minAmount,
					Maximum: &maxAmount,
				},
				"currency": {
					Type: TypeString,
					Enum: []string{"USD", "EUR", "GBP"},
				},
			},
			Required:             []string{"account_id", "amount", "currency"},
			AdditionalProperties: false,
		},
	})

	testCases := []struct {
		toolName string
		args     map[string]interface{}
	}{
		// 1. Valid read_file
		{
			toolName: "read_file",
			args:     map[string]interface{}{"path": "config.json"},
		},
		// 2. Missing required field in read_file
		{
			toolName: "read_file",
			args:     map[string]interface{}{},
		},
		// 3. Unexpected argument in read_file
		{
			toolName: "read_file",
			args:     map[string]interface{}{"path": "config.json", "inject_flag": "malicious"},
		},
		// 4. Valid transfer_funds
		{
			toolName: "transfer_funds",
			args: map[string]interface{}{
				"account_id": "acct_9876543210ab",
				"amount":     250.0,
				"currency":   "USD",
			},
		},
		// 5. Pattern & Enum mismatch in transfer_funds
		{
			toolName: "transfer_funds",
			args: map[string]interface{}{
				"account_id": "INVALID_ACCT_FORMAT!",
				"amount":     50000.0, // Exceeds maximum 10000.0
				"currency":   "BITCOIN", // Not in Enum
			},
		},
		// 6. Type mismatch (number passed where string expected)
		{
			toolName: "read_file",
			args:     map[string]interface{}{"path": 12345},
		},
	}

	var results []SchemaValidationResult
	valid := 0
	invalid := 0

	for _, tc := range testCases {
		res := reg.ValidateArguments(tc.toolName, tc.args)
		results = append(results, res)
		if res.Valid {
			valid++
		} else {
			invalid++
		}
	}

	return SchemaSummary{
		TotalValidated: len(results),
		ValidCount:     valid,
		InvalidCount:   invalid,
		Duration:       time.Since(start),
		Evaluations:    results,
	}
}
