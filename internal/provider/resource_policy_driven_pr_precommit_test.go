package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nullValueFor builds a properly typed null value for any schema attribute type,
// so a config can be assembled with only the attributes under test populated.
func nullValueFor(t *testing.T, ctx context.Context, at attr.Type) attr.Value {
	t.Helper()

	v, err := at.ValueFromTerraform(ctx, tftypes.NewValue(at.TerraformType(ctx), nil))
	require.NoError(t, err)
	return v
}

// runPolicyDrivenPRPrecommitValidateConfig drives the real ValidateConfig with only
// the pre-commit attributes populated. A non-nil precommitHooks (possibly empty)
// sets update_precommit_file; a non-nil customConfig sets custom_precommit_config.
func runPolicyDrivenPRPrecommitValidateConfig(t *testing.T, precommitHooks *[]string, customConfig *string) *fwresource.ValidateConfigResponse {
	t.Helper()

	ctx := context.Background()
	r := &policyDrivenPRResource{}

	schemaResp := &fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "schema errors: %v", schemaResp.Diagnostics)
	schema := schemaResp.Schema

	optionsType, ok := schema.Attributes["auto_remediation_options"].GetType().(types.ObjectType)
	require.True(t, ok, "auto_remediation_options should be an object")

	// Start from an all-null options object so this test stays valid as unrelated
	// attributes are added to the resource.
	optionValues := make(map[string]attr.Value, len(optionsType.AttrTypes))
	for name, at := range optionsType.AttrTypes {
		optionValues[name] = nullValueFor(t, ctx, at)
	}

	if precommitHooks != nil {
		elems := make([]attr.Value, 0, len(*precommitHooks))
		for _, hook := range *precommitHooks {
			elems = append(elems, types.StringValue(hook))
		}
		list, diags := types.ListValue(types.StringType, elems)
		require.False(t, diags.HasError(), "hook list: %v", diags)
		optionValues["update_precommit_file"] = list
	}

	if customConfig != nil {
		cpcType, ok := optionsType.AttrTypes["custom_precommit_config"].(types.ObjectType)
		require.True(t, ok, "custom_precommit_config should be an object")
		cpc, diags := types.ObjectValue(cpcType.AttrTypes, map[string]attr.Value{
			"config":                        types.StringValue(*customConfig),
			"update_existing_configuration": types.BoolValue(false),
		})
		require.False(t, diags.HasError(), "custom config object: %v", diags)
		optionValues["custom_precommit_config"] = cpc
	}

	options, diags := types.ObjectValue(optionsType.AttrTypes, optionValues)
	require.False(t, diags.HasError(), "options object: %v", diags)

	// selected_repos must be non-empty, otherwise ValidateConfig returns early on
	// that error and never reaches the pre-commit check.
	selectedRepos, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("widgets")})
	require.False(t, diags.HasError(), "selected repos: %v", diags)

	model := policyDrivenPRModel{
		ID:                    types.StringNull(),
		Owner:                 types.StringValue("test-org"),
		AutoRemdiationOptions: options,
		SelectedRepos:         selectedRepos,
		SelectedReposFilter:   nullValueFor(t, ctx, schema.Attributes["selected_repos_filter"].GetType()).(types.Object),
		ExcludedRepos:         types.ListNull(types.StringType),
	}

	plan := tfsdk.Plan{Schema: schema}
	require.False(t, plan.Set(ctx, model).HasError())

	resp := &fwresource.ValidateConfigResponse{}
	r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: schema},
	}, resp)
	return resp
}

// TestPolicyDrivenPRResource_ValidateConfig_PrecommitModesAreMutuallyExclusive covers
// the two pre-commit remediation modes. Selecting hooks (update_precommit_file) and
// pasting a full .pre-commit-config.yaml (custom_precommit_config) cannot be combined,
// because the API rejects such a payload. Catching it at plan time gives a clearer
// error than a failed apply.
func TestPolicyDrivenPRResource_ValidateConfig_PrecommitModesAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	customConfig := "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.18.4\n    hooks:\n      - id: gitleaks\n"
	hooks := []string{"gitleaks"}
	noHooks := []string{}
	blankConfig := "   \n"

	testCases := []struct {
		name          string
		hooks         *[]string
		customConfig  *string
		expectedError bool
	}{
		{
			name:          "both modes set is rejected",
			hooks:         &hooks,
			customConfig:  &customConfig,
			expectedError: true,
		},
		{
			name:          "hooks only is allowed",
			hooks:         &hooks,
			customConfig:  nil,
			expectedError: false,
		},
		{
			name:          "custom config only is allowed",
			hooks:         nil,
			customConfig:  &customConfig,
			expectedError: false,
		},
		{
			// Clearing the hook selection alongside a custom config is legitimate,
			// so an empty (non-null) list must not be treated as a conflict.
			name:          "custom config with an empty hook list is allowed",
			hooks:         &noHooks,
			customConfig:  &customConfig,
			expectedError: false,
		},
		{
			// A whitespace-only config is not a real custom config, so the hook
			// selection still applies and must not be rejected.
			name:          "blank custom config with hooks is allowed",
			hooks:         &hooks,
			customConfig:  &blankConfig,
			expectedError: false,
		},
		{
			name:          "neither mode set is allowed",
			hooks:         nil,
			customConfig:  nil,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := runPolicyDrivenPRPrecommitValidateConfig(t, tc.hooks, tc.customConfig)

			if tc.expectedError {
				require.True(t, resp.Diagnostics.HasError(), "expected a mutual-exclusion error")
				assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "mutually exclusive")
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}
