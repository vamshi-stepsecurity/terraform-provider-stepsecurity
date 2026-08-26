package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// Hierarchical structure for policy attachments
type PolicyAttachments struct {
	Org      *OrgResource `json:"org,omitempty"`
	Clusters []string     `json:"clusters,omitempty"`
}

type OrgResource struct {
	Name       string         `json:"name"`         // org name
	ApplyToOrg bool           `json:"apply_to_org"` // if true, applies to entire org
	Repos      []RepoResource `json:"repos,omitempty"`
}

type RepoResource struct {
	Name        string   `json:"name"`                // repo name
	ApplyToRepo bool     `json:"apply_to_repo"`       // if true, applies to entire repo
	Workflows   []string `json:"workflows,omitempty"` // specific workflows
}

// Main policy struct with embedded policy details
type GitHubPolicyStorePolicy struct {
	Owner                 string             `json:"owner"`
	PolicyName            string             `json:"policyName"`
	AllowedEndpoints      []string           `json:"allowed_endpoints"`
	DeniedEndpoints       []string           `json:"denied_endpoints,omitempty"`
	EgressPolicy          string             `json:"egress_policy"`
	DisableTelemetry      bool               `json:"disable_telemetry"`
	DisableSudo           bool               `json:"disable_sudo"`
	DisableFileMonitoring bool               `json:"disable_file_monitoring"`
	Lockdown              *LockdownConfig    `json:"lockdown,omitempty"`
	Attachments           *PolicyAttachments `json:"attachments,omitempty"`
}

type LockdownConfig struct {
	Enabled    bool     `json:"enabled"`
	Detections []string `json:"detections,omitempty"` // List of detections to enable for lockdown (empty = none enabled) "Privileged-Container", "Runner-Worker-Memory-Read", "Reverse-Shell"
}

func (c *APIClient) CreateGitHubPolicyStorePolicy(ctx context.Context, policy *GitHubPolicyStorePolicy) error {
	if policy == nil {
		return fmt.Errorf("empty policy provided")
	}

	// Create policy without attachments for API call
	policyForCreation := &GitHubPolicyStorePolicy{
		Owner:                 policy.Owner,
		PolicyName:            policy.PolicyName,
		AllowedEndpoints:      policy.AllowedEndpoints,
		DeniedEndpoints:       policy.DeniedEndpoints,
		EgressPolicy:          policy.EgressPolicy,
		DisableTelemetry:      policy.DisableTelemetry,
		DisableSudo:           policy.DisableSudo,
		DisableFileMonitoring: policy.DisableFileMonitoring,
		Lockdown:              policy.Lockdown,
		// Explicitly omit Attachments for creation
	}

	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, policy.Owner, policy.PolicyName)
	_, err := c.post(ctx, URI, policyForCreation)
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}
	return nil
}

func (c *APIClient) GetGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) (*GitHubPolicyStorePolicy, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, owner, policyName)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	var policy GitHubPolicyStorePolicy
	if err := json.Unmarshal(respBody, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &policy, nil
}

func (c *APIClient) DeleteGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, owner, policyName)
	_, err := c.delete(ctx, URI)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	return nil
}

// New hierarchical attachment request structure
type GitHubPolicyAttachRequest struct {
	Org      *OrgResource `json:"org,omitempty"`
	Clusters []string     `json:"clusters,omitempty"`
}

func (c *APIClient) AttachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string, request *GitHubPolicyAttachRequest) error {
	if request == nil {
		return fmt.Errorf("empty attach request provided")
	}
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s/attach", c.BaseURL, owner, policyName)
	_, err := c.post(ctx, URI, request)
	if err != nil {
		return fmt.Errorf("failed to attach policy: %w", err)
	}
	return nil
}

func (c *APIClient) DetachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s/attach", c.BaseURL, owner, policyName)
	_, err := c.delete(ctx, URI)
	if err != nil {
		return fmt.Errorf("failed to detach policy: %w", err)
	}
	return nil
}
