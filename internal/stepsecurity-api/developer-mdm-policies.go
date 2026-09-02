package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Developer MDM categories, spec versions, and policy modes.
const (
	DeveloperMDMCategoryIDEExtension    = "ide_extension"
	DeveloperMDMTargetVSCode            = "vscode"
	DeveloperMDMSpecVersionIDEExtension = 1
	DeveloperMDMModeAllowlist           = "allowlist"
	DeveloperMDMModeBlocklist           = "blocklist"

	// DeveloperMDMCategoryPackageConfig governs a device's package-manager configuration
	// file (v1: the npm user-level .npmrc), pointing it at the tenant's StepSecurity secure
	// registry.
	DeveloperMDMCategoryPackageConfig = "package_config"
	// DeveloperMDMTargetNPM is the package_config target for the npm ecosystem. An omitted
	// package_config target defaults to it.
	DeveloperMDMTargetNPM = "npm"
	// DeveloperMDMSpecVersionPackageConfig is the only supported package_config spec version.
	DeveloperMDMSpecVersionPackageConfig = 1
	// DeveloperMDMRegistryTypeStepSecurity is the only registry type package_config supports
	// in v1: the tenant's StepSecurity secure registry.
	DeveloperMDMRegistryTypeStepSecurity = "stepsecurity"
)

// Enforcement channels for a Developer MDM profile. dmg means the StepSecurity agent writes
// the managed settings itself; mdm means it only verifies what the organization's own MDM
// delivered. Required by the backend on create and update.
const (
	DeveloperMDMEnforcementDMG = "dmg"
	DeveloperMDMEnforcementMDM = "mdm"
)

// DeveloperMDMPolicy is the backend representation of a Developer MDM policy.
type DeveloperMDMPolicy struct {
	CustomerID  string          `json:"customer_id,omitempty"`
	PolicyID    string          `json:"policy_id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Category    string          `json:"category,omitempty"`
	Target      string          `json:"target,omitempty"`
	SpecVersion int             `json:"spec_version,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	Spec        json.RawMessage `json:"spec,omitempty"`
	CreatedBy   string          `json:"created_by,omitempty"`
	CreatedAt   string          `json:"created_at,omitempty"`
	UpdatedBy   string          `json:"updated_by,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
}

// DeveloperMDMPolicyRequest is the create/update request body.
type DeveloperMDMPolicyRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Category    string          `json:"category"`
	Target      string          `json:"target"`
	SpecVersion int             `json:"spec_version"`
	Mode        string          `json:"mode"`
	Spec        json.RawMessage `json:"spec"`
}

// DeveloperMDMMaxGalleryServiceURLLen mirrors the backend cap on gallery_service_url.
const DeveloperMDMMaxGalleryServiceURLLen = 2048

// DeveloperMDMIDEExtensionSpec is the typed spec for ide_extension policies. An unset
// GalleryServiceURL is omitted rather than stored as an empty key.
type DeveloperMDMIDEExtensionSpec struct {
	Rules             []DeveloperMDMIDEExtensionRule `json:"rules"`
	GalleryServiceURL string                         `json:"gallery_service_url,omitempty"`
}

// DeveloperMDMIDEExtensionRule is a single IDE extension allow/block rule.
type DeveloperMDMIDEExtensionRule struct {
	Publisher string   `json:"publisher"`
	Name      string   `json:"name,omitempty"`
	Versions  []string `json:"versions,omitempty"`
	Stable    bool     `json:"stable,omitempty"`
	Comment   string   `json:"comment,omitempty"`
}

// DeveloperMDMPackageConfigSpec is the typed spec for package_config policies. It carries
// only the registry selector; the concrete registry URL and tenant auth key are injected
// backend-side when the policy is compiled, so no secret ever travels through the provider.
type DeveloperMDMPackageConfigSpec struct {
	Registry DeveloperMDMRegistryRef `json:"registry"`
}

// DeveloperMDMRegistryRef selects which registry the managed npm config points at. v1
// accepts only type "stepsecurity" (the tenant's StepSecurity secure registry).
type DeveloperMDMRegistryRef struct {
	Type string `json:"type"`
}

// DeveloperMDMProfile is the backend representation of a Developer MDM profile.
type DeveloperMDMProfile struct {
	CustomerID  string                 `json:"customer_id,omitempty"`
	ProfileID   string                 `json:"profile_id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	PolicyIDs   []string               `json:"policy_ids,omitempty"`
	Enforcement string                 `json:"enforcement,omitempty"`
	Assignment  DeveloperMDMAssignment `json:"assignment"`
	CreatedBy   string                 `json:"created_by,omitempty"`
	CreatedAt   string                 `json:"created_at,omitempty"`
	UpdatedBy   string                 `json:"updated_by,omitempty"`
	UpdatedAt   string                 `json:"updated_at,omitempty"`
}

// DeveloperMDMProfileRequest is the create/update request body. Enforcement is always sent
// so an unset channel surfaces the backend's 400 instead of being dropped from the request.
type DeveloperMDMProfileRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	PolicyIDs   []string               `json:"policy_ids"`
	Enforcement string                 `json:"enforcement"`
	Assignment  DeveloperMDMAssignment `json:"assignment"`
}

// DeveloperMDMAssignment describes how a profile is assigned to devices.
type DeveloperMDMAssignment struct {
	AllDevices bool     `json:"all_devices"`
	DeviceIDs  []string `json:"device_ids,omitempty"`
}

// Export artifact formats for ide_extension. mobileconfig is the default; plist is the bare
// macOS preferences file, available only for os=macos.
const (
	DeveloperMDMExportFormatMobileconfig = "mobileconfig"
	DeveloperMDMExportFormatPlist        = "plist"
)

// DeveloperMDMExportArtifact is a compiled MDM artifact for a given OS/category.
// Content holds the decoded artifact body, not the escaped HTTP JSON string.
// Format and PreferenceDomain are set by the backend for macOS only.
type DeveloperMDMExportArtifact struct {
	OS               string `json:"os"`
	OSDisplayName    string `json:"os_display_name"`
	Category         string `json:"category"`
	Target           string `json:"target"`
	Format           string `json:"format,omitempty"`
	Filename         string `json:"filename"`
	ContentType      string `json:"content_type"`
	Content          string `json:"content"`
	Hash             string `json:"hash"`
	PreferenceDomain string `json:"preference_domain,omitempty"`
	Notes            string `json:"notes,omitempty"`
}

// DeveloperMDMComplianceView is one runtime compliance row. EvaluatedEnforcement is the
// channel the last report ran under, which can lag a profile's current channel while a
// switch propagates. Diff stays raw JSON because its per-setting values are a union of
// bool, string, and array that no single Terraform type expresses.
type DeveloperMDMComplianceView struct {
	DeviceID             string          `json:"device_id"`
	Category             string          `json:"category"`
	Target               string          `json:"target"`
	ProfileID            string          `json:"profile_id,omitempty"`
	State                string          `json:"state"`
	DesiredHash          string          `json:"desired_hash,omitempty"`
	AppliedHash          string          `json:"applied_hash,omitempty"`
	LastSeenAt           int64           `json:"last_seen_at,omitempty"`
	AgentVersion         string          `json:"agent_version,omitempty"`
	Platform             string          `json:"platform,omitempty"`
	EvaluatedAt          string          `json:"evaluated_at,omitempty"`
	EvaluatedEnforcement string          `json:"evaluated_enforcement,omitempty"`
	Diff                 json.RawMessage `json:"diff,omitempty"`
}

// DeveloperMDMDeviceComplianceResponse wraps compliance rows for one device.
type DeveloperMDMDeviceComplianceResponse struct {
	DeviceID   string                       `json:"device_id"`
	Compliance []DeveloperMDMComplianceView `json:"compliance"`
}

// DeveloperMDMProfileComplianceResponse wraps compliance rows for one profile.
type DeveloperMDMProfileComplianceResponse struct {
	ProfileID  string                       `json:"profile_id"`
	Compliance []DeveloperMDMComplianceView `json:"compliance"`
}

type developerMDMPolicyListResponse struct {
	Policies []DeveloperMDMPolicy `json:"policies"`
}

type developerMDMProfileListResponse struct {
	Profiles []DeveloperMDMProfile `json:"profiles"`
}

// developerMDMPath builds a Developer MDM API URL. The format string is
// appended after ".../developer-mdm" and receives the remaining args.
func (c *APIClient) developerMDMPath(format string, args ...any) string {
	return fmt.Sprintf("%s/v1/%s/developer-mdm"+format, append([]any{c.BaseURL, c.Customer}, args...)...)
}

func (c *APIClient) CreateDeveloperMDMPolicy(ctx context.Context, req DeveloperMDMPolicyRequest) (*DeveloperMDMPolicy, error) {
	body, err := c.post(ctx, c.developerMDMPath("/policies"), req)
	if err != nil {
		return nil, fmt.Errorf("failed to create developer MDM policy: %w", err)
	}
	var policy DeveloperMDMPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM policy response: %w", err)
	}
	return &policy, nil
}

func (c *APIClient) ListDeveloperMDMPolicies(ctx context.Context) ([]DeveloperMDMPolicy, error) {
	body, err := c.get(ctx, c.developerMDMPath("/policies"))
	if err != nil {
		return nil, fmt.Errorf("failed to list developer MDM policies: %w", err)
	}
	var resp developerMDMPolicyListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM policies response: %w", err)
	}
	return resp.Policies, nil
}

func (c *APIClient) GetDeveloperMDMPolicy(ctx context.Context, policyID string) (*DeveloperMDMPolicy, error) {
	body, err := c.get(ctx, c.developerMDMPath("/policies/%s", url.PathEscape(policyID)))
	if err != nil {
		return nil, fmt.Errorf("failed to get developer MDM policy: %w", err)
	}
	var policy DeveloperMDMPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM policy response: %w", err)
	}
	return &policy, nil
}

func (c *APIClient) UpdateDeveloperMDMPolicy(ctx context.Context, policyID string, req DeveloperMDMPolicyRequest) (*DeveloperMDMPolicy, error) {
	body, err := c.put(ctx, c.developerMDMPath("/policies/%s", url.PathEscape(policyID)), req)
	if err != nil {
		return nil, fmt.Errorf("failed to update developer MDM policy: %w", err)
	}
	var policy DeveloperMDMPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM policy response: %w", err)
	}
	return &policy, nil
}

func (c *APIClient) DeleteDeveloperMDMPolicy(ctx context.Context, policyID string) error {
	_, err := c.delete(ctx, c.developerMDMPath("/policies/%s", url.PathEscape(policyID)))
	if err != nil {
		return fmt.Errorf("failed to delete developer MDM policy: %w", err)
	}
	return nil
}

func (c *APIClient) CreateDeveloperMDMProfile(ctx context.Context, req DeveloperMDMProfileRequest) (*DeveloperMDMProfile, error) {
	body, err := c.post(ctx, c.developerMDMPath("/profiles"), req)
	if err != nil {
		return nil, fmt.Errorf("failed to create developer MDM profile: %w", err)
	}
	var profile DeveloperMDMProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM profile response: %w", err)
	}
	return &profile, nil
}

func (c *APIClient) ListDeveloperMDMProfiles(ctx context.Context) ([]DeveloperMDMProfile, error) {
	body, err := c.get(ctx, c.developerMDMPath("/profiles"))
	if err != nil {
		return nil, fmt.Errorf("failed to list developer MDM profiles: %w", err)
	}
	var resp developerMDMProfileListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM profiles response: %w", err)
	}
	return resp.Profiles, nil
}

func (c *APIClient) GetDeveloperMDMProfile(ctx context.Context, profileID string) (*DeveloperMDMProfile, error) {
	body, err := c.get(ctx, c.developerMDMPath("/profiles/%s", url.PathEscape(profileID)))
	if err != nil {
		return nil, fmt.Errorf("failed to get developer MDM profile: %w", err)
	}
	var profile DeveloperMDMProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM profile response: %w", err)
	}
	return &profile, nil
}

func (c *APIClient) UpdateDeveloperMDMProfile(ctx context.Context, profileID string, req DeveloperMDMProfileRequest) (*DeveloperMDMProfile, error) {
	body, err := c.put(ctx, c.developerMDMPath("/profiles/%s", url.PathEscape(profileID)), req)
	if err != nil {
		return nil, fmt.Errorf("failed to update developer MDM profile: %w", err)
	}
	var profile DeveloperMDMProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM profile response: %w", err)
	}
	return &profile, nil
}

func (c *APIClient) DeleteDeveloperMDMProfile(ctx context.Context, profileID string) error {
	_, err := c.delete(ctx, c.developerMDMPath("/profiles/%s", url.PathEscape(profileID)))
	if err != nil {
		return fmt.Errorf("failed to delete developer MDM profile: %w", err)
	}
	return nil
}

// ExportDeveloperMDMProfile fetches the compiled MDM artifact for a profile.
// The HTTP response encodes the artifact body as a JSON string; json.Unmarshal
// decodes it so DeveloperMDMExportArtifact.Content holds the real file body.
func (c *APIClient) ExportDeveloperMDMProfile(ctx context.Context, profileID, os, category, target, format string) (*DeveloperMDMExportArtifact, error) {
	uri := c.developerMDMPath("/profiles/%s/export", url.PathEscape(profileID))
	query := url.Values{}
	query.Set("os", os)
	if category != "" {
		query.Set("category", category)
	}
	if target != "" {
		query.Set("target", target)
	}
	if format != "" {
		query.Set("format", format)
	}
	uri += "?" + query.Encode()

	body, err := c.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to export developer MDM profile: %w", err)
	}
	var artifact DeveloperMDMExportArtifact
	if err := json.Unmarshal(body, &artifact); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM export response: %w", err)
	}
	return &artifact, nil
}

func (c *APIClient) GetDeveloperMDMDeviceCompliance(ctx context.Context, deviceID string) (*DeveloperMDMDeviceComplianceResponse, error) {
	body, err := c.get(ctx, c.developerMDMPath("/devices/%s/compliance", url.PathEscape(deviceID)))
	if err != nil {
		return nil, fmt.Errorf("failed to get developer MDM device compliance: %w", err)
	}
	var resp DeveloperMDMDeviceComplianceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM device compliance response: %w", err)
	}
	return &resp, nil
}

func (c *APIClient) GetDeveloperMDMProfileCompliance(ctx context.Context, profileID string) (*DeveloperMDMProfileComplianceResponse, error) {
	body, err := c.get(ctx, c.developerMDMPath("/profiles/%s/compliance", url.PathEscape(profileID)))
	if err != nil {
		return nil, fmt.Errorf("failed to get developer MDM profile compliance: %w", err)
	}
	var resp DeveloperMDMProfileComplianceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse developer MDM profile compliance response: %w", err)
	}
	return &resp, nil
}
