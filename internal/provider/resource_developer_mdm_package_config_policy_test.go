package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestDeveloperMDMPackageConfigPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMPackageConfigPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, name := range []string{"id", "policy_id", "name", "description", "target", "registry_type", "created_by", "created_at", "updated_by", "updated_at"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
	// package_config has no user-facing mode or rules, unlike ide_extension.
	assert.NotContains(t, attrs, "mode")
	assert.NotContains(t, attrs, "rules")
}

func TestDeveloperMDMPackageConfigPolicy_BuildRequestDefaults(t *testing.T) {
	t.Parallel()

	model := developerMDMPackageConfigPolicyModel{
		Name:        types.StringValue("npm secure registry"),
		Description: types.StringValue("route installs through StepSecurity"),
		// target and registry_type omitted: builder must default them.
		Target:       types.StringNull(),
		RegistryType: types.StringNull(),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMPackageConfigPolicyRequest(model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, "npm secure registry", req.Name)
	assert.Equal(t, "route installs through StepSecurity", req.Description)
	assert.Equal(t, stepsecurityapi.DeveloperMDMCategoryPackageConfig, req.Category)
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, req.Target)
	assert.Equal(t, stepsecurityapi.DeveloperMDMSpecVersionPackageConfig, req.SpecVersion)
	assert.Equal(t, stepsecurityapi.DeveloperMDMModeAllowlist, req.Mode)

	var spec stepsecurityapi.DeveloperMDMPackageConfigSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, spec.Registry.Type)
}

func TestDeveloperMDMPackageConfigPolicy_BuildRequestExplicitValues(t *testing.T) {
	t.Parallel()

	model := developerMDMPackageConfigPolicyModel{
		Name:         types.StringValue("npm"),
		Target:       types.StringValue(stepsecurityapi.DeveloperMDMTargetNPM),
		RegistryType: types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMPackageConfigPolicyRequest(model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, req.Target)
	assert.JSONEq(t, `{"registry":{"type":"stepsecurity"}}`, string(req.Spec))
}

func TestDeveloperMDMPackageConfigPolicy_ApplyToModel(t *testing.T) {
	t.Parallel()

	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID:    "pol-123",
		Name:        "npm secure registry",
		Description: "desc",
		Category:    stepsecurityapi.DeveloperMDMCategoryPackageConfig,
		Target:      stepsecurityapi.DeveloperMDMTargetNPM,
		SpecVersion: stepsecurityapi.DeveloperMDMSpecVersionPackageConfig,
		Mode:        stepsecurityapi.DeveloperMDMModeAllowlist,
		Spec:        json.RawMessage(`{"registry":{"type":"stepsecurity"}}`),
		CreatedBy:   "alice",
		CreatedAt:   "2026-07-23T00:00:00Z",
		UpdatedBy:   "bob",
		UpdatedAt:   "2026-07-23T01:00:00Z",
	}

	var model developerMDMPackageConfigPolicyModel
	var diags diag.Diagnostics
	applyDeveloperMDMPackageConfigPolicyToModel(policy, &model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, "pol-123", model.ID.ValueString())
	assert.Equal(t, "pol-123", model.PolicyID.ValueString())
	assert.Equal(t, "npm secure registry", model.Name.ValueString())
	assert.Equal(t, "desc", model.Description.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, model.Target.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, model.RegistryType.ValueString())
	assert.Equal(t, "alice", model.CreatedBy.ValueString())
	assert.Equal(t, "bob", model.UpdatedBy.ValueString())
}

func TestDeveloperMDMPackageConfigPolicy_ApplyToModelDefaultsTargetAndRegistry(t *testing.T) {
	t.Parallel()

	// Backend may echo an empty target / an empty spec on some paths; the model must
	// still land on the documented defaults rather than empty strings.
	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "pol-456",
		Name:     "npm",
		Category: stepsecurityapi.DeveloperMDMCategoryPackageConfig,
		Target:   "",
		Spec:     nil,
	}

	var model developerMDMPackageConfigPolicyModel
	var diags diag.Diagnostics
	applyDeveloperMDMPackageConfigPolicyToModel(policy, &model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, model.Target.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, model.RegistryType.ValueString())
	assert.True(t, model.Description.IsNull(), "empty description should map to null")
}

func TestDeveloperMDMPackageConfigPolicy_ApplyToModelRejectsWrongCategory(t *testing.T) {
	t.Parallel()

	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "pol-789",
		Category: stepsecurityapi.DeveloperMDMCategoryIDEExtension,
	}

	var model developerMDMPackageConfigPolicyModel
	var diags diag.Diagnostics
	applyDeveloperMDMPackageConfigPolicyToModel(policy, &model, &diags)
	assert.True(t, diags.HasError(), "expected an error for a non-package_config category")
}
