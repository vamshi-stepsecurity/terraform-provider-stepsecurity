package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// SecureRegistryControls represents the security policy configuration for a registry.
type SecureRegistryControls struct {
	Customer            string                      `json:"customer"`
	Registry            string                      `json:"registry"`
	CooldownPeriod      *CooldownPeriodControl      `json:"cooldown_period,omitempty"`
	CompromisedPackages *CompromisedPackagesControl `json:"compromised_packages,omitempty"`
	Typosquatting       *TyposquattingControl       `json:"typosquatting,omitempty"`
	CustomBlockList     *CustomBlockListControl     `json:"custom_block_list,omitempty"`
	NpmSettings         *NpmSettingsControl         `json:"npm_settings,omitempty"`
	UpdatedBy           string                      `json:"updated_by"`
	UpdatedAt           string                      `json:"updated_at"`
}

// CooldownPeriodControl blocks packages published within a configurable window.
type CooldownPeriodControl struct {
	Enabled       bool     `json:"enabled"`
	PeriodInDays  int      `json:"period_in_days"`
	ExemptionList []string `json:"exemption_list,omitempty"`
}

// CompromisedPackagesControl blocks packages flagged as compromised.
type CompromisedPackagesControl struct {
	Enabled bool `json:"enabled"`
}

// TyposquattingControl blocks package names that are heuristically similar to
// popular packages. It is an advisory control (fails open on detection errors).
// Only applicable when Registry == "npm"; the backend rejects enabling it for
// other registries. Whitelist entries override false-positive detections.
type TyposquattingControl struct {
	Enabled   bool     `json:"enabled"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// CustomBlockListControl explicitly blocks packages/versions matching glob patterns
// (exact names, `pkg@*` version globs, `@scope/*` for npm). Patterns are matched
// independently by the backend — order has no effect.
type CustomBlockListControl struct {
	Enabled  bool     `json:"enabled"`
	Patterns []string `json:"patterns,omitempty"`
}

// NpmSettingsControl holds npm-specific non-security registry settings. Unlike the
// other controls it has no "enabled" toggle — RewriteTarballURLs is itself the
// setting. Only applicable when Registry == "npm"; the backend rejects any non-nil
// value for other registries.
type NpmSettingsControl struct {
	RewriteTarballURLs bool `json:"rewrite_tarball_urls"`
}

// UpsertSecureRegistryControlsRequest is the PUT request body. Omitting a control
// preserves the existing backend value (partial upsert).
type UpsertSecureRegistryControlsRequest struct {
	CooldownPeriod      *CooldownPeriodControl      `json:"cooldown_period,omitempty"`
	CompromisedPackages *CompromisedPackagesControl `json:"compromised_packages,omitempty"`
	Typosquatting       *TyposquattingControl       `json:"typosquatting,omitempty"`
	CustomBlockList     *CustomBlockListControl     `json:"custom_block_list,omitempty"`
	NpmSettings         *NpmSettingsControl         `json:"npm_settings,omitempty"`
}

func (c *APIClient) GetRegistryControls(ctx context.Context, registry string) (*SecureRegistryControls, error) {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	var controls SecureRegistryControls
	if err := json.Unmarshal(body, &controls); err != nil {
		return nil, fmt.Errorf("failed to parse registry controls response: %w", err)
	}
	return &controls, nil
}

func (c *APIClient) UpsertRegistryControls(ctx context.Context, registry string, req UpsertSecureRegistryControlsRequest) (*SecureRegistryControls, error) {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	body, err := c.put(ctx, url, req)
	if err != nil {
		return nil, err
	}
	var controls SecureRegistryControls
	if err := json.Unmarshal(body, &controls); err != nil {
		return nil, fmt.Errorf("failed to parse upsert registry controls response: %w", err)
	}
	return &controls, nil
}

func (c *APIClient) DeleteRegistryControls(ctx context.Context, registry string) error {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	_, err := c.delete(ctx, url)
	return err
}
