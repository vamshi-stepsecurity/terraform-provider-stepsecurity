package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// TestSecureRegistryPolicyResource_Schema verifies the schema compiles and has expected attributes.
func TestSecureRegistryPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaReq := fwresource.SchemaRequest{}
	schemaResp := &fwresource.SchemaResponse{}

	NewSecureRegistryPolicyResource().Schema(ctx, schemaReq, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() returned errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, required := range []string{"registry", "cooldown_control", "compromised_packages_control", "typosquatting_control", "custom_block_list_control", "npm_settings"} {
		assert.Contains(t, attrs, required, "expected attribute %q in schema", required)
	}
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_BothControls verifies the request
// builder includes both controls when both are present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_BothControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	cooldownObj, cooldownDiag := buildTestCooldownObject(ctx, true, 7, []string{"react"})
	assert.False(t, cooldownDiag.HasError())

	compPkgObj, compDiag := buildTestCompromisedPackagesObject(true)
	assert.False(t, compDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CooldownPeriod)
	assert.True(t, req.CooldownPeriod.Enabled)
	assert.Equal(t, 7, req.CooldownPeriod.PeriodInDays)
	assert.Equal(t, []string{"react"}, req.CooldownPeriod.ExemptionList)
	assert.NotNil(t, req.CompromisedPackages)
	assert.True(t, req.CompromisedPackages.Enabled)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedControl verifies that
// removing a control from plan (null) while state had it causes an explicit disable.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedControl(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	// Previous state had cooldown enabled.
	prevCooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	prevState := &secureRegistryPolicyResourceModel{
		CooldownControl:            prevCooldownObj,
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	// New plan: cooldown removed (null), compromised packages added.
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)
	plan := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: compPkgObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	// Cooldown should be explicitly disabled (not omitted).
	assert.NotNil(t, req.CooldownPeriod)
	assert.False(t, req.CooldownPeriod.Enabled)
	// Compromised packages from plan.
	assert.NotNil(t, req.CompromisedPackages)
	assert.True(t, req.CompromisedPackages.Enabled)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_CustomBlockListAndNpmSettings verifies the
// request builder includes both new controls when present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_CustomBlockListAndNpmSettings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	blockListObj, blockListDiag := buildTestCustomBlockListObject(ctx, true, []string{"lodash@4*", "@scope/*"})
	assert.False(t, blockListDiag.HasError())

	npmSettingsObj, npmDiag := buildTestNpmSettingsObject(true)
	assert.False(t, npmDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: blockListObj,
		NpmSettings:            npmSettingsObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CustomBlockList)
	assert.True(t, req.CustomBlockList.Enabled)
	assert.ElementsMatch(t, []string{"lodash@4*", "@scope/*"}, req.CustomBlockList.Patterns)
	assert.NotNil(t, req.NpmSettings)
	assert.True(t, req.NpmSettings.RewriteTarballURLs)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedCustomBlockListAndNpmSettings
// verifies that removing custom_block_list_control/npm_settings from plan (null) while state had
// them causes an explicit disable/reset.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedCustomBlockListAndNpmSettings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	prevBlockListObj, _ := buildTestCustomBlockListObject(ctx, true, []string{"left-pad"})
	prevNpmSettingsObj, _ := buildTestNpmSettingsObject(true)
	prevState := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: prevBlockListObj,
		NpmSettings:            prevNpmSettingsObj,
	}

	plan := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
		NpmSettings:            types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CustomBlockList)
	assert.False(t, req.CustomBlockList.Enabled)
	assert.Equal(t, []string{}, req.CustomBlockList.Patterns)
	assert.NotNil(t, req.NpmSettings)
	assert.False(t, req.NpmSettings.RewriteTarballURLs)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_Typosquatting verifies the request
// builder includes the typosquatting control when present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_Typosquatting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	typosquattingObj, typosquattingDiag := buildTestTyposquattingObject(ctx, true, []string{"reactt", "lodashh"})
	assert.False(t, typosquattingDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: typosquattingObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.Typosquatting)
	assert.True(t, req.Typosquatting.Enabled)
	assert.ElementsMatch(t, []string{"reactt", "lodashh"}, req.Typosquatting.Whitelist)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedTyposquatting verifies that
// removing typosquatting_control from plan (null) while state had it causes an explicit disable.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedTyposquatting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	prevTyposquattingObj, _ := buildTestTyposquattingObject(ctx, true, []string{"reactt"})
	prevState := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: prevTyposquattingObj,
	}

	plan := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.Typosquatting)
	assert.False(t, req.Typosquatting.Enabled)
	assert.Equal(t, []string{}, req.Typosquatting.Whitelist)
}

// TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingDisabledNotInRefStaysNull verifies
// that a disabled typosquatting control does not get populated in state when not tracked.
func TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		Typosquatting: &stepsecurityapi.TyposquattingControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.TyposquattingControl.IsNull(), "disabled typosquatting should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingEnabledPopulatesState verifies
// that an enabled typosquatting control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		Typosquatting: &stepsecurityapi.TyposquattingControl{
			Enabled:   true,
			Whitelist: []string{"reactt"},
		},
	}

	model := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.TyposquattingControl.IsNull(), "enabled typosquatting should be in state")

	var typosquatting typosquattingControlModel
	diags = model.TyposquattingControl.As(ctx, &typosquatting, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, typosquatting.Enabled.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListDisabledNotInRefStaysNull verifies
// that a disabled custom block list control does not get populated in state when not tracked.
func TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.CustomBlockListControl.IsNull(), "disabled custom block list should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListEnabledPopulatesState verifies
// that an enabled custom block list control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{
			Enabled:  true,
			Patterns: []string{"lodash@4*"},
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.CustomBlockListControl.IsNull(), "enabled custom block list should be in state")

	var blockList customBlockListControlModel
	diags = model.CustomBlockListControl.As(ctx, &blockList, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, blockList.Enabled.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledNotInRefStaysNull verifies
// that npm_settings with RewriteTarballURLs=false does not get populated in state when the ref
// (current state) had null for it — mirrors the other controls' null-preservation rule.
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: false},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.NpmSettings.IsNull(), "npm_settings with rewrite_tarball_urls=false should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsEnabledPopulatesState verifies
// that npm_settings with RewriteTarballURLs=true is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	require.False(t, model.NpmSettings.IsNull(), "enabled npm_settings should be in state")

	var npmSettings npmSettingsModel
	diags = model.NpmSettings.As(ctx, &npmSettings, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, npmSettings.RewriteTarballURLs.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledButTrackedStaysInState verifies
// that npm_settings with RewriteTarballURLs=false stays populated when it was already tracked
// (e.g. user explicitly configured rewrite_tarball_urls = false).
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledButTrackedStaysInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	trackedObj := mustBuildTestNpmSettingsObject(t, false)
	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: trackedObj,
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: false},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.NpmSettings.IsNull(), "previously tracked npm_settings should remain in state even when false")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsNullForNonNpm verifies npm_settings
// stays null when the backend never returns it (e.g. pypi).
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsNullForNonNpm(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "pypi",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: nil,
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.NpmSettings.IsNull())
}

// TestSecureRegistryPolicyResource_ValidateConfig_NpmSettings exercises the real ValidateConfig
// method, asserting registry-gated controls (npm_settings, typosquatting_control,
// custom_block_list_control on maven) are rejected for unsupported registries and allowed
// where supported.
func TestSecureRegistryPolicyResource_ValidateConfig_NpmSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		registry               string
		npmSettings            types.Object
		typosquattingControl   types.Object
		customBlockListControl types.Object
		expectedError          bool
	}{
		{
			name:                   "npm_settings_allowed_for_npm",
			registry:               "npm",
			npmSettings:            mustBuildTestNpmSettingsObject(t, true),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "npm_settings_rejected_for_pypi",
			registry:               "pypi",
			npmSettings:            mustBuildTestNpmSettingsObject(t, true),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "npm_settings_absent_for_pypi",
			registry:               "pypi",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_allowed_for_npm",
			registry:               "npm",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_rejected_for_pypi",
			registry:               "pypi",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "typosquatting_control_rejected_for_maven",
			registry:               "maven",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "typosquatting_control_rejected_for_nuget",
			registry:               "nuget",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "custom_block_list_control_rejected_for_maven",
			registry:               "maven",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: mustBuildTestCustomBlockListObject(t, true, []string{"left-pad"}),
			expectedError:          true,
		},
		{
			name:                   "custom_block_list_control_allowed_for_nuget",
			registry:               "nuget",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: mustBuildTestCustomBlockListObject(t, true, []string{"left-pad"}),
			expectedError:          false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &secureRegistryPolicyResource{}

			model := secureRegistryPolicyResourceModel{
				Registry:                   types.StringValue(tc.registry),
				CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
				CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
				TyposquattingControl:       tc.typosquattingControl,
				CustomBlockListControl:     tc.customBlockListControl,
				NpmSettings:                tc.npmSettings,
			}

			config := testSecureRegistryPolicyConfig(t, model)
			resp := &fwresource.ValidateConfigResponse{}

			r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, resp)

			if tc.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}

// TestSecureRegistryPolicyResource_ValidateConfig_UnknownBlocksDeferValidation verifies that
// ValidateConfig does not raise a false-positive error when a gated block's value is Unknown
// (e.g. derived from a not-yet-computed reference) rather than concretely configured — Unknown
// is distinct from Null and must not be treated as "the user set this block".
func TestSecureRegistryPolicyResource_ValidateConfig_UnknownBlocksDeferValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		registry string
		model    func(m *secureRegistryPolicyResourceModel)
	}{
		{
			name:     "unknown_npm_settings_on_pypi",
			registry: "pypi",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.NpmSettings = types.ObjectUnknown(npmSettingsAttrTypes)
			},
		},
		{
			name:     "unknown_typosquatting_control_on_pypi",
			registry: "pypi",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.TyposquattingControl = types.ObjectUnknown(typosquattingControlAttrTypes)
			},
		},
		{
			name:     "unknown_custom_block_list_control_on_maven",
			registry: "maven",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.CustomBlockListControl = types.ObjectUnknown(customBlockListControlAttrTypes)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &secureRegistryPolicyResource{}

			model := secureRegistryPolicyResourceModel{
				Registry:                   types.StringValue(tc.registry),
				CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
				CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
				TyposquattingControl:       types.ObjectNull(typosquattingControlAttrTypes),
				CustomBlockListControl:     types.ObjectNull(customBlockListControlAttrTypes),
				NpmSettings:                types.ObjectNull(npmSettingsAttrTypes),
			}
			tc.model(&model)

			config := testSecureRegistryPolicyConfig(t, model)
			resp := &fwresource.ValidateConfigResponse{}

			r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, resp)

			assert.False(t, resp.Diagnostics.HasError(), "unknown block should defer validation, got: %v", resp.Diagnostics)
		})
	}
}

// TestSecureRegistryPolicyResource_applyAPIResponse_DisabledControlNotInRefStaysNull verifies
// that a disabled backend control does not get populated in state when the ref (current state)
// had null for that control.
func TestSecureRegistryPolicyResource_applyAPIResponse_DisabledControlNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:      false,
			PeriodInDays: 1,
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.CooldownControl.IsNull(), "disabled cooldown should remain null when not tracked")
	assert.True(t, model.CompromisedPackagesControl.IsNull(), "disabled compromised packages should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_EnabledControlPopulatesState verifies
// that an enabled backend control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_EnabledControlPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:       true,
			PeriodInDays:  14,
			ExemptionList: []string{"@babel/core"},
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: true,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.CooldownControl.IsNull(), "enabled cooldown should be in state")
	assert.False(t, model.CompromisedPackagesControl.IsNull(), "enabled compromised packages should be in state")

	var cooldown cooldownControlModel
	diags = model.CooldownControl.As(ctx, &cooldown, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, cooldown.Enabled.ValueBool())
	assert.Equal(t, int64(14), cooldown.PeriodInDays.ValueInt64())
}

// TestSecureRegistryPolicyResource_MockUpsert unit-tests Create flow with a mock client.
func TestSecureRegistryPolicyResource_MockUpsert(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}

	expectedResult := &stepsecurityapi.SecureRegistryControls{
		Customer:  "test-customer",
		Registry:  "npm",
		UpdatedBy: "test@example.com",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:      true,
			PeriodInDays: 7,
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: true,
		},
	}

	mockClient.On("UpsertRegistryControls", ctx, "npm", mock.AnythingOfType("stepsecurityapi.UpsertSecureRegistryControlsRequest")).
		Return(expectedResult, nil)

	r := &secureRegistryPolicyResource{client: mockClient}

	cooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)

	plan := &secureRegistryPolicyResourceModel{
		Registry:                   types.StringValue("npm"),
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	upsertReq := stepsecurityapi.UpsertSecureRegistryControlsRequest{
		CooldownPeriod:      &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{Enabled: true},
	}

	result, err := r.client.UpsertRegistryControls(ctx, "npm", upsertReq)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.CooldownPeriod.Enabled)
	assert.True(t, result.CompromisedPackages.Enabled)

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, plan, plan, result, &diags)
	assert.False(t, diags.HasError())
	assert.False(t, plan.CooldownControl.IsNull())
	assert.False(t, plan.CompromisedPackagesControl.IsNull())

	mockClient.AssertExpectations(t)
}

// TestSecureRegistryPolicyResource_MockUpsert_Maven unit-tests Create flow for the maven
// registry, which only supports cooldown_control and compromised_packages_control.
func TestSecureRegistryPolicyResource_MockUpsert_Maven(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}

	expectedResult := &stepsecurityapi.SecureRegistryControls{
		Customer:  "test-customer",
		Registry:  "maven",
		UpdatedBy: "test@example.com",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:      true,
			PeriodInDays: 7,
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: true,
		},
	}

	mockClient.On("UpsertRegistryControls", ctx, "maven", mock.AnythingOfType("stepsecurityapi.UpsertSecureRegistryControlsRequest")).
		Return(expectedResult, nil)

	r := &secureRegistryPolicyResource{client: mockClient}

	cooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)

	plan := &secureRegistryPolicyResourceModel{
		Registry:                   types.StringValue("maven"),
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	upsertReq := stepsecurityapi.UpsertSecureRegistryControlsRequest{
		CooldownPeriod:      &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{Enabled: true},
	}

	result, err := r.client.UpsertRegistryControls(ctx, "maven", upsertReq)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.CooldownPeriod.Enabled)
	assert.True(t, result.CompromisedPackages.Enabled)

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, plan, plan, result, &diags)
	assert.False(t, diags.HasError())
	assert.False(t, plan.CooldownControl.IsNull())
	assert.False(t, plan.CompromisedPackagesControl.IsNull())

	mockClient.AssertExpectations(t)
}

// TestAccSecureRegistryPolicyResource is an acceptance test that runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create with both controls
			{
				Config: testAccSecureRegistryPolicyConfig(true, 7, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "registry", "npm"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.period_in_days", "7"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
			// ImportState
			{
				ResourceName:      "stepsecurity_secure_registry_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update: change period_in_days
			{
				Config: testAccSecureRegistryPolicyConfig(true, 14, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.period_in_days", "14"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
			// Update: disable cooldown by removing the block
			{
				Config: testAccSecureRegistryPolicyOnlyCompromisedConfig(true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckNoResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
			// Update: add custom_block_list_control and npm_settings
			{
				Config: testAccSecureRegistryPolicyNpmFullConfig(true, []string{"lodash@4*", "@scope/*"}, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.patterns.#", "2"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "npm_settings.rewrite_tarball_urls", "true"),
				),
			},
			// Update: change patterns list and disable tarball rewriting
			{
				Config: testAccSecureRegistryPolicyNpmFullConfig(true, []string{"requests@*"}, false),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.patterns.#", "1"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "npm_settings.rewrite_tarball_urls", "false"),
				),
			},
			// Update: remove custom_block_list_control block
			{
				Config: testAccSecureRegistryPolicyOnlyCompromisedConfig(true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckNoResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control"),
				),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_PypiBlockList is an acceptance test covering
// custom_block_list_control on pypi (npm_settings is not applicable there).
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_PypiBlockList(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyPypiBlockListConfig(true, []string{"requests@2.25.0", "insecure-package"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "registry", "pypi"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "custom_block_list_control.patterns.#", "2"),
				),
			},
			// npm_settings is not applicable to pypi — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyPypiWithNpmSettingsConfig(),
				ExpectError: regexp.MustCompile(`npm_settings is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Typosquatting is an acceptance test covering
// typosquatting_control on npm, including plan-time rejection on other registries.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Typosquatting(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyTyposquattingConfig(true, []string{"reactt", "lodashh"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "registry", "npm"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "typosquatting_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "typosquatting_control.exemption_list.#", "2"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.typosquatting_test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// typosquatting_control is not applicable to pypi — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyPypiWithTyposquattingConfig(),
				ExpectError: regexp.MustCompile(`typosquatting_control is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Maven is an acceptance test covering the maven registry,
// which supports cooldown_control/compromised_packages_control but not custom_block_list_control.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Maven(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyMavenConfig(true, 7, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "registry", "maven"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "cooldown_control.period_in_days", "7"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "compromised_packages_control.enabled", "true"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.maven_test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// custom_block_list_control is not applicable to maven — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyMavenWithBlockListConfig(),
				ExpectError: regexp.MustCompile(`custom_block_list_control is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Nuget is an acceptance test covering the nuget registry,
// which supports the same controls as npm minus typosquatting_control/npm_settings.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Nuget(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyNugetBlockListConfig(true, []string{"Newtonsoft.Json@1*"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "registry", "nuget"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "custom_block_list_control.patterns.#", "1"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.nuget_test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// --- helpers ---

func buildTestCooldownObject(ctx context.Context, enabled bool, periodInDays int64, exemptions []string) (types.Object, diag.Diagnostics) {
	var exemptionList types.Set
	var diags diag.Diagnostics
	if exemptions != nil {
		vals := make([]attr.Value, len(exemptions))
		for i, v := range exemptions {
			vals[i] = types.StringValue(v)
		}
		exemptionList, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(cooldownControlAttrTypes), diags
		}
	} else {
		exemptionList = types.SetNull(types.StringType)
	}
	return types.ObjectValue(cooldownControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(enabled),
		"period_in_days": types.Int64Value(periodInDays),
		"exemption_list": exemptionList,
	})
}

func buildTestCompromisedPackagesObject(enabled bool) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(compromisedPackagesControlAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(enabled),
	})
}

func buildTestTyposquattingObject(ctx context.Context, enabled bool, exemptions []string) (types.Object, diag.Diagnostics) {
	var exemptionList types.Set
	var diags diag.Diagnostics
	if exemptions != nil {
		vals := make([]attr.Value, len(exemptions))
		for i, v := range exemptions {
			vals[i] = types.StringValue(v)
		}
		exemptionList, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(typosquattingControlAttrTypes), diags
		}
	} else {
		exemptionList = types.SetNull(types.StringType)
	}
	return types.ObjectValue(typosquattingControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(enabled),
		"exemption_list": exemptionList,
	})
}

func buildTestCustomBlockListObject(ctx context.Context, enabled bool, patterns []string) (types.Object, diag.Diagnostics) {
	var patternsSet types.Set
	var diags diag.Diagnostics
	if patterns != nil {
		vals := make([]attr.Value, len(patterns))
		for i, v := range patterns {
			vals[i] = types.StringValue(v)
		}
		patternsSet, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(customBlockListControlAttrTypes), diags
		}
	} else {
		patternsSet = types.SetNull(types.StringType)
	}
	return types.ObjectValue(customBlockListControlAttrTypes, map[string]attr.Value{
		"enabled":  types.BoolValue(enabled),
		"patterns": patternsSet,
	})
}

func buildTestNpmSettingsObject(rewriteTarballURLs bool) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(npmSettingsAttrTypes, map[string]attr.Value{
		"rewrite_tarball_urls": types.BoolValue(rewriteTarballURLs),
	})
}

func mustBuildTestNpmSettingsObject(t *testing.T, rewriteTarballURLs bool) types.Object {
	t.Helper()
	obj, diags := buildTestNpmSettingsObject(rewriteTarballURLs)
	require.False(t, diags.HasError())
	return obj
}

func mustBuildTestTyposquattingObject(t *testing.T, enabled bool) types.Object {
	t.Helper()
	obj, diags := buildTestTyposquattingObject(context.Background(), enabled, nil)
	require.False(t, diags.HasError())
	return obj
}

func mustBuildTestCustomBlockListObject(t *testing.T, enabled bool, patterns []string) types.Object {
	t.Helper()
	obj, diags := buildTestCustomBlockListObject(context.Background(), enabled, patterns)
	require.False(t, diags.HasError())
	return obj
}

func testSecureRegistryPolicySchema(t *testing.T) resourceschema.Schema {
	t.Helper()

	r := &secureRegistryPolicyResource{}
	resp := &fwresource.SchemaResponse{}
	r.Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testSecureRegistryPolicyConfig(t *testing.T, model secureRegistryPolicyResourceModel) tfsdk.Config {
	t.Helper()

	schema := testSecureRegistryPolicySchema(t)
	plan := tfsdk.Plan{Schema: schema}
	diags := plan.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return tfsdk.Config{Raw: plan.Raw, Schema: schema}
}

func testAccSecureRegistryPolicyConfig(cooldownEnabled bool, periodInDays int, compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  cooldown_control = {
    enabled        = %t
    period_in_days = %d
  }

  compromised_packages_control = {
    enabled = %t
  }
}
`, cooldownEnabled, periodInDays, compromisedEnabled)
}

func testAccSecureRegistryPolicyOnlyCompromisedConfig(compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  compromised_packages_control = {
    enabled = %t
  }
}
`, compromisedEnabled)
}

func quotedPatternsList(patterns []string) string {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func testAccSecureRegistryPolicyNpmFullConfig(blockListEnabled bool, patterns []string, rewriteTarballURLs bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  compromised_packages_control = {
    enabled = true
  }

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }

  npm_settings = {
    rewrite_tarball_urls = %t
  }
}
`, blockListEnabled, quotedPatternsList(patterns), rewriteTarballURLs)
}

func testAccSecureRegistryPolicyPypiBlockListConfig(blockListEnabled bool, patterns []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "pypi_test" {
  registry = "pypi"

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }
}
`, blockListEnabled, quotedPatternsList(patterns))
}

func testAccSecureRegistryPolicyPypiWithNpmSettingsConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "pypi_test" {
  registry = "pypi"

  npm_settings = {
    rewrite_tarball_urls = true
  }
}
`
}

func testAccSecureRegistryPolicyTyposquattingConfig(enabled bool, exemptions []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "typosquatting_test" {
  registry = "npm"

  typosquatting_control = {
    enabled        = %t
    exemption_list = %s
  }
}
`, enabled, quotedPatternsList(exemptions))
}

func testAccSecureRegistryPolicyPypiWithTyposquattingConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "pypi_test" {
  registry = "pypi"

  typosquatting_control = {
    enabled = true
  }
}
`
}

func testAccSecureRegistryPolicyMavenConfig(cooldownEnabled bool, periodInDays int, compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "maven_test" {
  registry = "maven"

  cooldown_control = {
    enabled        = %t
    period_in_days = %d
  }

  compromised_packages_control = {
    enabled = %t
  }
}
`, cooldownEnabled, periodInDays, compromisedEnabled)
}

func testAccSecureRegistryPolicyMavenWithBlockListConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "maven_test" {
  registry = "maven"

  custom_block_list_control = {
    enabled  = true
    patterns = ["left-pad@*"]
  }
}
`
}

func testAccSecureRegistryPolicyNugetBlockListConfig(blockListEnabled bool, patterns []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "nuget_test" {
  registry = "nuget"

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }
}
`, blockListEnabled, quotedPatternsList(patterns))
}
