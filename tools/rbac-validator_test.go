package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/component-helpers/auth/rbac/validation"
)

func TestValidationInputOutput(t *testing.T) {
	tests := []struct {
		name           string
		userRules      []rbacv1.PolicyRule
		referenceRules []rbacv1.PolicyRule
		expectedCovers bool
	}{
		{
			name: "user has subset permissions",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "user has excess permissions",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
			expectedCovers: false,
		},
		{
			name: "identical permissions",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "user has partial overlap",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods", "services"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
			expectedCovers: false,
		},
		{
			name:      "empty user rules",
			userRules: []rbacv1.PolicyRule{},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "APIGroups overlap - user has subset of groups",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps"},
					Resources: []string{"pods", "deployments"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps", "extensions"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "APIGroups overlap - user has extra group",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps", "networking.k8s.io"},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: false,
		},
		{
			name: "wildcard APIGroups in reference",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"custom.io", "another.io"},
					Resources: []string{"customresources"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "core vs named APIGroups",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods", "services"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps"},
					Resources: []string{"*"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "resourceNames constraint - user within allowed names",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"my-config"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get", "list"},
					ResourceNames: []string{"my-config", "other-config"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "resourceNames constraint - user exceeds allowed names",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"my-config", "forbidden-config"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"*"},
					ResourceNames: []string{"my-config"},
				},
			},
			expectedCovers: false,
		},
		{
			name: "resourceNames - reference has no constraint means all allowed",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"any-secret"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list"},
					// No ResourceNames constraint = access to all
				},
			},
			expectedCovers: true,
		},
		{
			name: "multiple rules - all must be covered",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
					Verbs:     []string{"list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "multiple rules - one not covered",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{"networking.k8s.io"},
					Resources: []string{"networkpolicies"},
					Verbs:     []string{"create"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: false,
		},
		{
			name: "subresources access - exact match needed",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods/log"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods/log", "pods/status"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
		},
		{
			name: "subresources access - wildcard doesn't work as expected",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods/log"},
					Verbs:     []string{"get"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods/*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: false, // Kubernetes validation doesn't treat * as wildcard in resources
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the validation logic directly
			covers, _ := validation.Covers(tt.referenceRules, tt.userRules)
			if covers != tt.expectedCovers {
				t.Errorf("validation.Covers() = %v, want %v", covers, tt.expectedCovers)
			}
		})
	}
}

func TestComplexMultiAPIGroupRole(t *testing.T) {
	// Test based on actual konflux-admin-user-actions role from infra-deployments
	// https://github.com/redhat-appstudio/infra-deployments/blob/main/components/konflux-rbac/production/base/konflux-admin-user-actions.yaml

	konfluxAdminRules := []rbacv1.PolicyRule{
		// AppStudio resources - comprehensive permissions
		{
			APIGroups: []string{"appstudio.redhat.com"},
			Resources: []string{
				"applications", "components", "componentdetectionqueries",
				"environments", "gitopsdeployments", "gitopsdeploymentsyncruns",
				"promotionruns", "releaseplanadmissions", "releaseplans",
				"releases", "snapshots", "snapshotenvironmentbindings",
				"spiaccesschecks", "spiaccesstokenbindings", "spiaccesstokens",
				"spifilebindings", "spifilecontentproviders", "spifilecontentrequest",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Tekton resources
		{
			APIGroups: []string{"tekton.dev"},
			Resources: []string{"pipelineruns", "taskruns"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		// Core resources - secrets and configmaps
		{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Project control resources
		{
			APIGroups: []string{"projctl.konflux.dev"},
			Resources: []string{"projectdevelopmentstreams"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// RBAC resources
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"roles", "rolebindings"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Service accounts
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		// Limited pod access
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "pods/log"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Batch resources
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs", "cronjobs"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Results access
		{
			APIGroups: []string{"results.tekton.dev"},
			Resources: []string{"results", "records", "logs"},
			Verbs:     []string{"get", "list"},
		},
	}

	tests := []struct {
		name           string
		userRules      []rbacv1.PolicyRule
		referenceRules []rbacv1.PolicyRule
		expectedCovers bool
		description    string
	}{
		{
			name:           "partial admin permissions should be covered",
			userRules:      konfluxAdminRules[:3], // Only first 3 rules
			referenceRules: konfluxAdminRules,     // Full admin rules
			expectedCovers: true,
			description:    "Subset of admin permissions should be properly validated",
		},
		{
			name: "user exceeding admin in one APIGroup",
			userRules: append(konfluxAdminRules, rbacv1.PolicyRule{
				APIGroups: []string{"custom.io"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			}),
			referenceRules: konfluxAdminRules,
			expectedCovers: false,
			description:    "Adding extra APIGroup should fail validation",
		},
		{
			name: "user with subset verbs across multiple APIGroups",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications", "components"},
					Verbs:     []string{"get", "list", "watch"}, // Subset of admin verbs
				},
				{
					APIGroups: []string{"tekton.dev"},
					Resources: []string{"pipelineruns"},
					Verbs:     []string{"get", "list"}, // Subset of admin verbs
				},
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"get", "list"}, // Subset of admin verbs
				},
			},
			referenceRules: konfluxAdminRules,
			expectedCovers: true,
			description:    "Read-only subset across multiple APIGroups should be valid",
		},
		{
			name: "user exceeding verb permissions in one APIGroup",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"tekton.dev"},
					Resources: []string{"pipelineruns"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"}, // More than admin allows
				},
			},
			referenceRules: konfluxAdminRules,
			expectedCovers: false,
			description:    "Exceeding verb permissions in tekton.dev should fail (admin only allows up to patch)",
		},
		{
			name: "wildcard matching test",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications", "components", "environments"},
					Verbs:     []string{"get", "list", "create"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
			description:    "Wildcard reference should cover specific permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			covers, _ := validation.Covers(tt.referenceRules, tt.userRules)
			if covers != tt.expectedCovers {
				t.Errorf("validation.Covers() = %v, want %v\nDescription: %s",
					covers, tt.expectedCovers, tt.description)

				// Print details for debugging
				t.Logf("User rules: %+v", tt.userRules)
				t.Logf("Reference rules: %+v", tt.referenceRules)
			}
		})
	}
}

func TestRealWorldKonfluxRoles(t *testing.T) {
	// These test cases are based on actual roles from infra-deployments
	tests := []struct {
		name           string
		userRules      []rbacv1.PolicyRule
		referenceRules []rbacv1.PolicyRule
		expectedCovers bool
		description    string
	}{
		{
			name: "konflux-contributor subset of konflux-admin",
			userRules: []rbacv1.PolicyRule{
				// Simplified konflux-contributor-user-actions rules
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps", "secrets"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications", "components"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// Simplified konflux-admin-user-actions rules (more permissive)
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
			description:    "Contributor permissions should be subset of admin permissions",
		},
		{
			name: "custom role exceeds konflux-contributor",
			userRules: []rbacv1.PolicyRule{
				// Custom role trying to exceed contributor permissions
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"create", "update", "patch", "delete"}, // More than contributor
				},
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// konflux-contributor-user-actions rules
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps", "secrets"},
					Verbs:     []string{"get", "list", "watch"}, // Read-only for secrets
				},
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications", "components"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
			},
			expectedCovers: false,
			description:    "Custom role with secret write access should exceed contributor permissions",
		},
		{
			name: "konflux-rhel-read-events custom role",
			userRules: []rbacv1.PolicyRule{
				// Custom role based on konflux-rhel-read-events
				{
					APIGroups: []string{""},
					Resources: []string{"events"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// Based on actual konflux-rhel-read-events-role.yaml
				{
					APIGroups: []string{""},
					Resources: []string{"events"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
			expectedCovers: true,
			description:    "Exact match of rhel events role should be valid",
		},
		{
			name: "release pipeline role subset check",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"releases"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// Simplified release-pipeline-resource-role
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"releases", "releaseplans", "releaseplanadmissions"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
			},
			expectedCovers: true,
			description:    "Read-only release access should be subset of release pipeline role",
		},
		{
			name: "tekton resources access attempt",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"tekton.dev"},
					Resources: []string{"pipelineruns", "taskruns"},
					Verbs:     []string{"create", "update", "patch"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// Standard konflux roles don't usually give direct tekton access
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"applications", "components"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: false,
			description:    "Direct tekton access should not be covered by standard appstudio permissions",
		},
		{
			name: "enterprisecontractpolicy viewer role",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"enterprisecontractpolicies"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				// Based on enterprisecontractpolicy-viewer-role for managed tenants
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"enterprisecontractpolicies"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
			expectedCovers: true,
			description:    "ECP viewer should match exactly with reference role",
		},
		{
			name: "multiple apigroups real scenario",
			userRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"", "apps", "appstudio.redhat.com"},
					Resources: []string{"configmaps", "deployments", "applications"},
					Verbs:     []string{"get", "list"},
				},
			},
			referenceRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"*"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"appstudio.redhat.com"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedCovers: true,
			description:    "Multi-apigroup access covered by separate reference rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			covers, _ := validation.Covers(tt.referenceRules, tt.userRules)
			if covers != tt.expectedCovers {
				t.Errorf("validation.Covers() = %v, want %v\nDescription: %s",
					covers, tt.expectedCovers, tt.description)

				// Print details for debugging
				t.Logf("User rules: %+v", tt.userRules)
				t.Logf("Reference rules: %+v", tt.referenceRules)
			}
		})
	}
}

func TestBinaryIntegration(t *testing.T) {
	// Build the binary first
	cmd := exec.Command("go", "build", "-o", "rbac-validator-test", "rbac-validator.go")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer func() { _ = os.Remove("rbac-validator-test") }()

	tests := []struct {
		name           string
		input          ValidationInput
		expectedCovers bool
		shouldError    bool
	}{
		{
			name: "valid input - subset",
			input: ValidationInput{
				UserRules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				ReferenceRules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"*"},
						Resources: []string{"*"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCovers: true,
			shouldError:    false,
		},
		{
			name: "valid input - excess permissions",
			input: ValidationInput{
				UserRules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"*"},
						Resources: []string{"*"},
						Verbs:     []string{"*"},
					},
				},
				ReferenceRules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			},
			expectedCovers: false,
			shouldError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare input
			inputJSON, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			// Run the binary
			cmd := exec.Command("./rbac-validator-test")
			cmd.Stdin = bytes.NewReader(inputJSON)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v, stderr: %s", err, stderr.String())
			}

			if !tt.shouldError {
				// Parse output
				var output ValidationOutput
				if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
					t.Fatalf("Failed to unmarshal output: %v, stdout: %s", err, stdout.String())
				}

				if output.Covers != tt.expectedCovers {
					t.Errorf("Binary output covers = %v, want %v", output.Covers, tt.expectedCovers)
				}

				if output.Error != "" {
					t.Errorf("Unexpected error in output: %s", output.Error)
				}
			}
		})
	}
}

func TestInvalidJSON(t *testing.T) {
	// Build the binary first
	cmd := exec.Command("go", "build", "-o", "rbac-validator-test", "rbac-validator.go")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer func() { _ = os.Remove("rbac-validator-test") }()

	// Test with invalid JSON
	cmd = exec.Command("./rbac-validator-test")
	cmd.Stdin = bytes.NewReader([]byte("invalid json"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Error("Expected error with invalid JSON but got none")
	}

	// Should still produce valid JSON output with error
	var output ValidationOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("Failed to unmarshal error output: %v, stdout: %s", err, stdout.String())
	}

	if output.Covers {
		t.Error("Expected covers=false for invalid input")
	}

	if output.Error == "" {
		t.Error("Expected error message for invalid input")
	}
}
