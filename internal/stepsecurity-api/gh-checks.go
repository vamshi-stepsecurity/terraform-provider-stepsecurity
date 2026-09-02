package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

var (
	AvailableControls = map[string]string{
		"Maven Package Compromised Updates": "maven_package_compromised_updates",
		"Maven Package Cooldown":            "maven_package_cooldown",
		"NPM Package Compromised Updates":   "npm_package_compromised_updates",
		"NPM Package Cooldown":              "npm_package_recent_release_guard",
		"NuGet Package Compromised Updates": "nuget_package_compromised_updates",
		"NuGet Package Cooldown":            "nuget_package_cooldown",
		"PWN Request":                       "pwn_request_check",
		"PyPI Package Compromised Updates":  "pypi_package_compromised_updates",
		"PyPI Package Cooldown":             "pypi_package_cooldown",
		"Script Injection":                  "script_injection_check",
	}
)

type ChecksConfig struct {
	// map of check name -> config
	Checks                             map[string]CheckConfig `json:"checks"`
	EnableBaselineCheckForAllNewRepos  *bool                  `json:"enable_baseline_check_for_all_new_repos"`
	EnableRequiredChecksForAllNewRepos *bool                  `json:"enable_required_checks_for_all_new_repos"`
	EnableOptionalChecksForAllNewRepos *bool                  `json:"enable_optional_checks_for_all_new_repos"`
	CustomDescription                  string                 `json:"custom_description"`
}

type CheckConfig struct {
	Enabled  bool           `json:"enabled"`
	Type     string         `json:"type"`
	Settings map[string]any `json:"settings"`
}

type CheckOptions struct {
	Baseline          bool `json:"baseline"`
	RunRequiredChecks bool `json:"run_required_checks"`
	RunOptionalChecks bool `json:"run_optional_checks"`
}

type GitHubPRChecksConfig struct {
	ChecksConfig
	Repos map[string]CheckOptions `json:"repos"`
}

func GetAvailableControls() []string {
	var controls []string
	for control := range AvailableControls {
		controls = append(controls, control)
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i] < controls[j]
	})
	return controls
}

// controlNamesByCheck is the reverse of AvailableControls, so the display name for a check
// never has to be maintained separately from the check name it maps to.
var controlNamesByCheck = func() map[string]string {
	names := make(map[string]string, len(AvailableControls))
	for name, check := range AvailableControls {
		names[check] = name
	}
	return names
}()

// GetControlName returns the display name for a check name, or "" if the check is unknown.
func GetControlName(control string) string {
	return controlNamesByCheck[control]
}

func (c *APIClient) GetPRChecksConfig(ctx context.Context, owner string) (GitHubPRChecksConfig, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/checks/config", c.BaseURL, owner)
	prChecksConfig := GitHubPRChecksConfig{}

	respBody, err := c.get(ctx, URI)
	if err != nil {
		return prChecksConfig, fmt.Errorf("failed to get control settings: %w", err)
	}

	if err := json.Unmarshal(respBody, &prChecksConfig); err != nil {
		return prChecksConfig, fmt.Errorf("failed to unmarshal control settings: %w", err)
	}

	return prChecksConfig, nil
}

func (c *APIClient) UpdatePRChecksConfig(ctx context.Context, owner string, req GitHubPRChecksConfig) error {

	if getBooleanPointerValue(req.EnableBaselineCheckForAllNewRepos) ||
		getBooleanPointerValue(req.EnableRequiredChecksForAllNewRepos) ||
		getBooleanPointerValue(req.EnableOptionalChecksForAllNewRepos) {
		existingConfig, err := c.GetPRChecksConfig(ctx, owner)
		if err != nil {
			return fmt.Errorf("failed to get PR checks config: %w", err)
		}
		for repo := range existingConfig.Repos {
			if _, ok := req.Repos[repo]; !ok {
				req.Repos[repo] = CheckOptions{
					Baseline:          getBooleanPointerValue(req.EnableBaselineCheckForAllNewRepos),
					RunRequiredChecks: getBooleanPointerValue(req.EnableRequiredChecksForAllNewRepos),
					RunOptionalChecks: getBooleanPointerValue(req.EnableOptionalChecksForAllNewRepos),
				}
			}
		}

	}

	URI := fmt.Sprintf("%s/v1/github/%s/checks/config", c.BaseURL, owner)
	_, err := c.put(ctx, URI, req)
	if err != nil {
		return fmt.Errorf("failed to update PR checks config: %w", err)
	}

	return nil
}

func (c *APIClient) DeletePRChecksConfig(ctx context.Context, owner string) error {

	config, err := c.GetPRChecksConfig(ctx, owner)
	if err != nil {
		return fmt.Errorf("failed to get PR checks config: %w", err)
	}

	// disable all controls
	for controlName, control := range config.ChecksConfig.Checks {
		control.Enabled = false
		control.Settings = nil
		config.ChecksConfig.Checks[controlName] = control
	}

	// disable all checks for all repos
	for repo, checkOptions := range config.Repos {
		checkOptions.RunRequiredChecks = false
		checkOptions.RunOptionalChecks = false
		checkOptions.Baseline = false
		config.Repos[repo] = checkOptions
	}

	// disable checks for all repos
	config.ChecksConfig.EnableBaselineCheckForAllNewRepos = toPointer(false)
	config.ChecksConfig.EnableRequiredChecksForAllNewRepos = toPointer(false)
	config.ChecksConfig.EnableOptionalChecksForAllNewRepos = toPointer(false)
	config.ChecksConfig.CustomDescription = ""

	URI := fmt.Sprintf("%s/v1/github/%s/checks/config", c.BaseURL, owner)
	_, err = c.put(ctx, URI, config)
	if err != nil {
		return fmt.Errorf("failed to delete PR checks config: %w", err)
	}

	return nil
}

func getBooleanPointerValue(value *bool) bool {
	if value != nil {
		return *value
	}
	return false
}

func toPointer(value bool) *bool {
	return &value
}
