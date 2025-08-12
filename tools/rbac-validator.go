// Package main implements an RBAC validator using Kubernetes validation logic
package main

import (
	"encoding/json"
	"fmt"
	"os"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/component-helpers/auth/rbac/validation"
)

// ValidationInput represents the input structure for RBAC validation
type ValidationInput struct {
	UserRules      []rbacv1.PolicyRule `json:"userRules"`
	ReferenceRules []rbacv1.PolicyRule `json:"referenceRules"`
}

// ValidationOutput represents the output structure for RBAC validation
type ValidationOutput struct {
	Covers bool   `json:"covers"`
	Error  string `json:"error,omitempty"`
}

func main() {
	var input ValidationInput

	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		output := ValidationOutput{
			Covers: false,
			Error:  fmt.Sprintf("Error decoding input: %v", err),
		}
		_ = json.NewEncoder(os.Stdout).Encode(output)
		os.Exit(1)
	}

	// Use Kubernetes validation logic
	covers, _ := validation.Covers(input.ReferenceRules, input.UserRules)

	output := ValidationOutput{
		Covers: covers,
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding output: %v\n", err)
		os.Exit(1)
	}
}
