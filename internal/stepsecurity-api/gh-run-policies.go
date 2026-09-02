package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type RunPolicy struct {
	Owner         string          `json:"owner,omitempty"`
	Customer      string          `json:"customer,omitempty"`
	PolicyID      string          `json:"policy_id,omitempty"`
	Name          string          `json:"name,omitempty"`
	CreatedBy     string          `json:"created_by,omitempty"`
	CreatedAt     time.Time       `json:"created_at,omitempty"`
	LastUpdatedBy string          `json:"last_updated_by,omitempty"`
	LastUpdatedAt time.Time       `json:"last_updated_at,omitempty"`
	PolicyConfig  RunPolicyConfig `json:"policy_config,omitempty"`
	AllRepos      bool            `json:"all_repos,omitempty"`
	AllOrgs       bool            `json:"all_orgs,omitempty"`
	Repositories  []string        `json:"repositories,omitempty"`
}

type RunPolicyConfig struct {
	Owner                          string              `json:"owner"`
	Name                           string              `json:"name"`
	EnableActionPolicy             bool                `json:"enable_action_policy,omitempty"`
	AllowedActions                 map[string]string   `json:"allowed_actions,omitempty"`
	EnableHardenRunnerPolicy       bool                `json:"enable_harden_runner_policy,omitempty"`
	HardenRunnerTargetLabels       []string            `json:"harden_runner_labels,omitempty"`
	HardenRunnerCustomActions      []string            `json:"harden_runner_custom_actions,omitempty"`
	EnableRunsOnPolicy             bool                `json:"enable_runs_on_policy,omitempty"`
	DisallowedRunnerLabels         map[string]struct{} `json:"disallowed_runner_labels,omitempty"`
	EnableStandardRunnerLabels     bool                `json:"enable_standard_runner_labels,omitempty"`
	EnableSecretsPolicy            bool                `json:"enable_secrets_policy,omitempty"`
	EnableCompromisedActionsPolicy bool                `json:"enable_compromised_actions_policy,omitempty"`
	RequirePinnedActions           bool                `json:"require_pinned_actions,omitempty"`
	PinnedActionsExemptions        []string            `json:"pinned_actions_exemptions,omitempty"`
	IsDryRun                       bool                `json:"is_dry_run,omitempty"`
	ExemptedUsers                  []string            `json:"exempted_users,omitempty"`
	BulkSecretsOnlyMode            bool                `json:"bulk_secrets_only_mode,omitempty"`
	PrCommentTemplate              string              `json:"pr_comment_template,omitempty"`
	RunsOnMode                     string              `json:"runs_on_mode,omitempty"`
	AllowedRunnerLabels            map[string]struct{} `json:"allowed_runner_labels,omitempty"`
	AllowedRunnerConstraints       map[string][]string `json:"allowed_runner_constraints,omitempty"`
	RequirePolicyStore             bool                `json:"require_policy_store,omitempty"`
	BlockJobContainer              bool                `json:"block_job_container,omitempty"`
	SecretsAnalyzeDefaultBranch    bool                `json:"secrets_analyze_default_branch,omitempty"`
}

type CreateRunPolicyRequest struct {
	Name         string          `json:"name"`
	PolicyConfig RunPolicyConfig `json:"policy_config"`
	AllRepos     bool            `json:"all_repos"`
	AllOrgs      bool            `json:"all_orgs"`
	Repositories []string        `json:"repositories"`
}

type UpdateRunPolicyRequest struct {
	Name         string          `json:"name"`
	PolicyConfig RunPolicyConfig `json:"policy_config"`
	AllRepos     bool            `json:"all_repos"`
	AllOrgs      bool            `json:"all_orgs"`
	Repositories []string        `json:"repositories"`
}

// ListRunPolicies retrieves all run policies for a given owner
func (c *APIClient) ListRunPolicies(ctx context.Context, owner string) ([]RunPolicy, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policies", c.BaseURL, owner)

	body, err := c.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to list run policies: %w", err)
	}

	var policies []RunPolicy
	err = json.Unmarshal(body, &policies)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal run policies response: %w", err)
	}

	return policies, nil
}

// CreateRunPolicy creates a new run policy
func (c *APIClient) CreateRunPolicy(ctx context.Context, owner string, policy CreateRunPolicyRequest) (*RunPolicy, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policies", c.BaseURL, owner)

	body, err := c.post(ctx, uri, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create run policy: %w", err)
	}

	var updatedPolicy RunPolicy
	err = json.Unmarshal(body, &updatedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updated run policy response: %w", err)
	}

	return &updatedPolicy, nil
}

// GetRunPolicy retrieves a specific run policy by policy ID
func (c *APIClient) GetRunPolicy(ctx context.Context, owner string, policyID string) (*RunPolicy, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policies/%s", c.BaseURL, owner, policyID)

	body, err := c.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to get run policy: %w", err)
	}

	var policy RunPolicy
	err = json.Unmarshal(body, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal run policy response: %w", err)
	}

	return &policy, nil
}

// UpdateRunPolicy updates an existing run policy
func (c *APIClient) UpdateRunPolicy(ctx context.Context, owner string, policyID string, policy UpdateRunPolicyRequest) (*RunPolicy, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policies/%s", c.BaseURL, owner, policyID)

	body, err := c.put(ctx, uri, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to update run policy: %w", err)
	}

	var updatedPolicy RunPolicy
	err = json.Unmarshal(body, &updatedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updated run policy response: %w", err)
	}

	return &updatedPolicy, nil
}

// DeleteRunPolicy deletes a run policy by policy ID
func (c *APIClient) DeleteRunPolicy(ctx context.Context, owner string, policyID string) error {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policies/%s", c.BaseURL, owner, policyID)

	_, err := c.delete(ctx, uri)
	if err != nil {
		return fmt.Errorf("failed to delete run policy: %w", err)
	}

	return nil
}
