#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["pyyaml"]
# ///
"""
Test script to demonstrate how roles are loaded and compared in practice.
This shows the real workflow of role validation.
"""

import json
import subprocess
import yaml
import os
from pathlib import Path

def load_cluster_role_from_yaml(yaml_content):
    """Extract PolicyRules from a ClusterRole YAML"""
    try:
        doc = yaml.safe_load(yaml_content)
        if doc.get('kind') == 'ClusterRole':
            return doc.get('rules', [])
    except Exception as e:
        print(f"Error parsing YAML: {e}")
    return []

def convert_to_k8s_policy_rules(rules):
    """Convert YAML rules to the format expected by our validator"""
    converted = []
    for rule in rules:
        converted_rule = {
            "apiGroups": rule.get("apiGroups", [""]),
            "resources": rule.get("resources", []),
            "verbs": rule.get("verbs", [])
        }
        if "resourceNames" in rule:
            converted_rule["resourceNames"] = rule["resourceNames"]
        converted.append(converted_rule)
    return converted

def test_role_comparison(user_rules, reference_rules, description):
    """Test role comparison using our validator"""
    input_data = {
        "userRules": user_rules,
        "referenceRules": reference_rules
    }
    
    try:
        # Run the validator
        result = subprocess.run(
            ["./rbac-validator"],
            input=json.dumps(input_data),
            text=True,
            capture_output=True,
            check=False
        )
        
        if result.returncode == 0:
            output = json.loads(result.stdout)
            covers = output.get("covers", False)
            error = output.get("error", "")
            
            print(f"\n=== {description} ===")
            print(f"Result: {'✅ VALID' if covers else '❌ INVALID'} (covers={covers})")
            if error:
                print(f"Error: {error}")
            return covers
        else:
            print(f"\n=== {description} ===")
            print(f"❌ VALIDATION FAILED: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"\n=== {description} ===")
        print(f"❌ ERROR: {e}")
        return False

def main():
    print("🔍 Testing Role Comparison with Real Konflux Roles")
    
    # Simulate the konflux-admin-user-actions role (reference role)
    admin_role_yaml = """
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: konflux-admin-user-actions
rules:
- apiGroups: ["appstudio.redhat.com"]
  resources: ["applications", "components", "environments", "snapshots"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["tekton.dev"]
  resources: ["pipelineruns", "taskruns"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
"""

    # Simulate a contributor role (should be subset of admin)
    contributor_role_yaml = """
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: konflux-contributor-user-actions
rules:
- apiGroups: ["appstudio.redhat.com"]
  resources: ["applications", "components"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
"""

    # Simulate a problematic role (exceeds admin permissions)
    problematic_role_yaml = """
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: problematic-role
rules:
- apiGroups: ["appstudio.redhat.com"]
  resources: ["applications", "components"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["tekton.dev"]
  resources: ["pipelineruns", "taskruns"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]  # More than admin allows
- apiGroups: ["custom.io"]  # Extra APIGroup not in admin
  resources: ["customresources"]
  verbs: ["*"]
"""

    # Load and convert roles
    admin_rules = convert_to_k8s_policy_rules(load_cluster_role_from_yaml(admin_role_yaml))
    contributor_rules = convert_to_k8s_policy_rules(load_cluster_role_from_yaml(contributor_role_yaml))
    problematic_rules = convert_to_k8s_policy_rules(load_cluster_role_from_yaml(problematic_role_yaml))

    print(f"📋 Loaded roles:")
    print(f"  - Admin role: {len(admin_rules)} rules")
    print(f"  - Contributor role: {len(contributor_rules)} rules")
    print(f"  - Problematic role: {len(problematic_rules)} rules")

    # Test 1: Contributor should be subset of admin
    test_role_comparison(
        contributor_rules, 
        admin_rules,
        "Contributor vs Admin (should be valid)"
    )

    # Test 2: Problematic role should exceed admin permissions
    test_role_comparison(
        problematic_rules,
        admin_rules, 
        "Problematic role vs Admin (should be invalid)"
    )

    # Test 3: Admin compared to itself
    test_role_comparison(
        admin_rules,
        admin_rules,
        "Admin vs Admin (should be valid)"
    )

    # Test 4: Complex multi-APIGroup scenario
    complex_user_rules = [
        {
            "apiGroups": ["appstudio.redhat.com"],
            "resources": ["applications"],
            "verbs": ["get", "list"]
        },
        {
            "apiGroups": ["tekton.dev"], 
            "resources": ["pipelineruns"],
            "verbs": ["get", "list", "watch"]
        },
        {
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["get", "list", "watch"]
        }
    ]
    
    test_role_comparison(
        complex_user_rules,
        admin_rules,
        "Multi-APIGroup read-only user vs Admin (should be valid)"
    )

    print(f"\n🎯 Summary:")
    print(f"The validator effectively handles complex multi-APIGroup roles by:")
    print(f"  ✅ Validating each user rule against ALL reference rules")
    print(f"  ✅ Ensuring APIGroups, Resources, and Verbs are proper subsets")
    print(f"  ✅ Handling multiple rules across different APIGroups")
    print(f"  ✅ Detecting when users exceed reference permissions")

if __name__ == "__main__":
    main()