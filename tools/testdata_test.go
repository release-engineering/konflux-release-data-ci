package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/component-helpers/auth/rbac/validation"
)

// PolicyRuleYAML represents a PolicyRule with proper YAML tags
type PolicyRuleYAML struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	Verbs           []string `yaml:"verbs"`
	ResourceNames   []string `yaml:"resourceNames,omitempty"`
	NonResourceURLs []string `yaml:"nonResourceURLs,omitempty"`
}

// RoleYAML represents the structure of a Role or ClusterRole YAML file
type RoleYAML struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace,omitempty"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Rules []PolicyRuleYAML `yaml:"rules"`
}

// toPolicyRule converts PolicyRuleYAML to rbacv1.PolicyRule
func (p PolicyRuleYAML) toPolicyRule() rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups:       p.APIGroups,
		Resources:       p.Resources,
		Verbs:           p.Verbs,
		ResourceNames:   p.ResourceNames,
		NonResourceURLs: p.NonResourceURLs,
	}
}

// loadRoleFromFile loads and parses a Role or ClusterRole YAML file
func loadRoleFromFile(path string) ([]rbacv1.PolicyRule, string, string, error) {
	data, err := os.ReadFile(path) // #nosec G304 - Path is controlled in test context
	if err != nil {
		return nil, "", "", err
	}

	var role RoleYAML
	if err := yaml.Unmarshal(data, &role); err != nil {
		return nil, "", "", err
	}

	// Convert YAML rules to rbacv1.PolicyRule
	rules := make([]rbacv1.PolicyRule, len(role.Rules))
	for i, yamlRule := range role.Rules {
		rules[i] = yamlRule.toPolicyRule()
	}

	description := role.Metadata.Annotations["description"]
	return rules, description, role.Kind, nil
}

func TestAllowedRoles(t *testing.T) {
	// Load reference role
	referenceRules, _, _, err := loadRoleFromFile("testdata/reference-role.yaml")
	if err != nil {
		t.Fatalf("Failed to load reference role: %v", err)
	}

	// Test all allowed roles
	allowedDir := "testdata/roles/allowed"
	files, err := filepath.Glob(filepath.Join(allowedDir, "*.yaml"))
	if err != nil {
		t.Fatalf("Failed to glob allowed roles: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("No allowed role test files found")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			userRules, description, kind, err := loadRoleFromFile(file)
			if err != nil {
				t.Fatalf("Failed to load role file %s: %v", file, err)
			}

			covers, _ := validation.Covers(referenceRules, userRules)
			if !covers {
				t.Errorf("%s %s should be allowed but validation failed.\nDescription: %s\nUser rules: %+v",
					kind, filepath.Base(file), description, userRules)
			} else {
				t.Logf("✅ %s %s correctly validated as allowed. Description: %s",
					kind, filepath.Base(file), description)
			}
		})
	}
}

func TestDeniedRoles(t *testing.T) {
	// Load reference role
	referenceRules, _, _, err := loadRoleFromFile("testdata/reference-role.yaml")
	if err != nil {
		t.Fatalf("Failed to load reference role: %v", err)
	}

	// Test all denied roles
	deniedDir := "testdata/roles/denied"
	files, err := filepath.Glob(filepath.Join(deniedDir, "*.yaml"))
	if err != nil {
		t.Fatalf("Failed to glob denied roles: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("No denied role test files found")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			userRules, description, kind, err := loadRoleFromFile(file)
			if err != nil {
				t.Fatalf("Failed to load role file %s: %v", file, err)
			}

			covers, _ := validation.Covers(referenceRules, userRules)
			if covers {
				t.Errorf("%s %s should be denied but validation passed.\nDescription: %s\nUser rules: %+v",
					kind, filepath.Base(file), description, userRules)
			} else {
				t.Logf("✅ %s %s correctly validated as denied. Description: %s",
					kind, filepath.Base(file), description)
			}
		})
	}
}

func TestBinaryWithTestData(t *testing.T) {
	// Load reference role
	referenceRules, _, _, err := loadRoleFromFile("testdata/reference-role.yaml")
	if err != nil {
		t.Fatalf("Failed to load reference role: %v", err)
	}

	// Test one allowed and one denied role through the binary
	testCases := []struct {
		name           string
		roleFile       string
		expectedCovers bool
	}{
		{
			name:           "allowed ClusterRole via binary",
			roleFile:       "testdata/roles/allowed/contributor-subset.yaml",
			expectedCovers: true,
		},
		{
			name:           "denied ClusterRole via binary",
			roleFile:       "testdata/roles/denied/exceeds-tekton-permissions.yaml",
			expectedCovers: false,
		},
		{
			name:           "allowed namespaced Role via binary",
			roleFile:       "testdata/roles/allowed/namespaced-contributor.yaml",
			expectedCovers: true,
		},
		{
			name:           "denied namespaced Role via binary",
			roleFile:       "testdata/roles/denied/namespaced-excessive.yaml",
			expectedCovers: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userRules, description, kind, err := loadRoleFromFile(tc.roleFile)
			if err != nil {
				t.Fatalf("Failed to load role file %s: %v", tc.roleFile, err)
			}

			// Test via binary (integration test)
			input := ValidationInput{
				UserRules:      userRules,
				ReferenceRules: referenceRules,
			}

			inputJSON, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			// Note: This assumes the binary is built - make sure it's available
			cmd := exec.Command("./rbac-validator")
			cmd.Stdin = bytes.NewReader(inputJSON)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			if err != nil {
				t.Fatalf("Binary execution failed: %v, stderr: %s", err, stderr.String())
			}

			var output ValidationOutput
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatalf("Failed to unmarshal binary output: %v", err)
			}

			if output.Covers != tc.expectedCovers {
				t.Errorf("Binary validation for %s %s: got covers=%v, want covers=%v\nDescription: %s",
					kind, filepath.Base(tc.roleFile), output.Covers, tc.expectedCovers, description)
			}

			if output.Error != "" {
				t.Errorf("Unexpected error from binary: %s", output.Error)
			}
		})
	}
}

func TestTestDataCompleteness(t *testing.T) {
	// Verify we have test cases for key scenarios
	allowedFiles, _ := filepath.Glob("testdata/roles/allowed/*.yaml")
	deniedFiles, _ := filepath.Glob("testdata/roles/denied/*.yaml")

	t.Logf("Found %d allowed test cases and %d denied test cases", len(allowedFiles), len(deniedFiles))

	if len(allowedFiles) < 3 {
		t.Error("Should have at least 3 allowed role test cases")
	}

	if len(deniedFiles) < 3 {
		t.Error("Should have at least 3 denied role test cases")
	}

	// Check for specific test scenarios
	expectedScenarios := map[string]bool{
		"contributor-subset":         false,
		"read-only-multiapi":         false,
		"namespaced-contributor":     false,
		"exceeds-tekton-permissions": false,
		"unauthorized-apigroup":      false,
		"excessive-pod-permissions":  false,
		"namespaced-excessive":       false,
	}

	allFiles := append(allowedFiles, deniedFiles...)
	for _, file := range allFiles {
		basename := strings.TrimSuffix(filepath.Base(file), ".yaml")
		if _, exists := expectedScenarios[basename]; exists {
			expectedScenarios[basename] = true
		}
	}

	for scenario, found := range expectedScenarios {
		if !found {
			t.Errorf("Missing test case for scenario: %s", scenario)
		}
	}
}
