package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

var (
	testOwner = "tf-acc-test"
)

// Helper function to create settings object for tests
func createSettingsObject(cooldownPeriod *int64, packages []string) types.Object {
	settingsMap := map[string]attr.Value{}

	if cooldownPeriod != nil {
		settingsMap["cool_down_period"] = types.Int64Value(*cooldownPeriod)
	} else {
		settingsMap["cool_down_period"] = types.Int64Null()
	}

	if packages != nil {
		elements := make([]attr.Value, len(packages))
		for i, pkg := range packages {
			elements[i] = types.StringValue(pkg)
		}
		settingsMap["packages_to_exempt_in_cooldown_check"], _ = types.ListValue(types.StringType, elements)
	} else {
		settingsMap["packages_to_exempt_in_cooldown_check"] = types.ListNull(types.StringType)
	}

	settingsType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"cool_down_period":                     types.Int64Type,
			"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
		},
	}

	obj, _ := types.ObjectValue(settingsType.AttrTypes, settingsMap)
	return obj
}

// Helper function to create null settings object for tests (for controls without settings)
func createNullSettingsObject() types.Object {
	return types.ObjectNull(map[string]attr.Type{
		"cool_down_period":                     types.Int64Type,
		"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
	})
}

// mustControlsList converts a []control slice into the types.List value that the
// "controls" attribute is now bound to.
func mustControlsList(controls []control) types.List {
	list, diags := types.ListValueFrom(context.Background(), controlObjectType(), controls)
	if diags.HasError() {
		panic(diagsToError(diags))
	}
	return list
}

// controlsListToSlice decodes a "controls" types.List back into a []control slice for assertions.
func controlsListToSlice(list types.List) []control {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var controls []control
	diags := list.ElementsAs(context.Background(), &controls, false)
	if diags.HasError() {
		panic(diagsToError(diags))
	}
	return controls
}

// mustChecksConfigObject converts a *checksConfig into the types.Object value that
// required_checks/optional_checks/baseline_check are now bound to. A nil cfg produces a null object.
func mustChecksConfigObject(cfg *checksConfig) types.Object {
	return encodeChecksConfig(context.Background(), cfg)
}

// mustValidateConfigRequest builds the ValidateConfigRequest for a githubChecksModel so tests can
// exercise the real ValidateConfig rather than a copy of its logic. Test cases leave attributes
// they don't care about as the Go zero value; those carry no element/attribute type, which the
// framework's strict type check rejects, so they are normalized to typed nulls here.
func mustValidateConfigRequest(t *testing.T, ctx context.Context, r *githubChecksResource, model githubChecksModel) resource.ValidateConfigRequest {
	t.Helper()

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics)
	}

	if model.Controls.IsNull() && model.Controls.ElementType(ctx) == nil {
		model.Controls = types.ListNull(controlObjectType())
	}
	for _, obj := range []*types.Object{&model.RequiredChecks, &model.OptionalChecks, &model.BaselineCheck} {
		if obj.IsNull() && len(obj.AttributeTypes(ctx)) == 0 {
			*obj = types.ObjectNull(checksConfigAttrTypes())
		}
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, model); diags.HasError() {
		t.Fatalf("unexpected diagnostics building config: %v", diags)
	}

	return resource.ValidateConfigRequest{Config: tfsdk.Config{Raw: plan.Raw, Schema: schemaResp.Schema}}
}

// checksConfigFromObject decodes a required_checks/optional_checks/baseline_check types.Object
// back into a *checksConfig for assertions.
func checksConfigFromObject(obj types.Object) *checksConfig {
	cfg, diags := decodeChecksConfig(context.Background(), obj)
	if diags.HasError() {
		panic(diagsToError(diags))
	}
	return cfg
}

func TestAccGithubChecksResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfig(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.control", "NPM Package Cooldown"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.enable", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.type", "required"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.cool_down_period", "5"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.0", "*"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigUpdated(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.cool_down_period", "10"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccGithubChecksResourceWithBaselineCheck(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithBaseline(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "baseline_check.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "baseline_check.repos.0", "*"),
				),
			},
		},
	})
}

func TestAccGithubChecksResourceWithPackageExemptions(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithPackageExemptions(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.0", "lodash"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.1", "express"),
				),
			},
		},
	})
}

func TestAccGithubChecksResourceWithMultipleRepos(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create with multiple repos in unsorted order
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithMultipleRepos(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.0", "gh-actions-test-repo-2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.1", "gh-actions-test-repo-1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "optional_checks.repos.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "optional_checks.repos.0", "gh-actions-test-repo-1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "optional_checks.repos.1", "gh-actions-test-repo-2"),
				),
			},
			// Update with different order - should still be sorted
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithMultipleReposUpdated(testOwner),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", testOwner),
					// Verify repos remain sorted after update
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.0", "gh-actions-test-repo-1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.1", "gh-actions-test-repo-2"),
					// Verify optional repos remain sorted
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "optional_checks.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "optional_checks.repos.0", "gh-actions-test-repo-1"),
				),
			},
		},
	})
}

func TestAccGithubChecksResourceWithOmitRepos(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	// t.Setenv("TF_ACC", "1")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithOmitRepos("sailikhith-stepsecurity"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", "sailikhith-stepsecurity"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.0", "*"),
					// Verify omit_repos are sorted alphabetically
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.omit_repos.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.omit_repos.0", "gh-actions-test-repo-2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.omit_repos.1", "gh-actions-test-repo-1"),
				),
			},
		},
	})
}

// Unit Tests
func TestGithubChecksResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_checks",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_checks",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			ctx := context.Background()

			req := resource.MetadataRequest{
				ProviderTypeName: tc.providerTypeName,
			}
			resp := &resource.MetadataResponse{}

			r.Metadata(ctx, req, resp)

			if resp.TypeName != tc.expected {
				t.Errorf("Expected TypeName %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestGithubChecksResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubChecksResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"owner", "controls", "required_checks", "optional_checks", "baseline_check"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}

	// Test that controls is optional
	if controlsAttr, exists := resp.Schema.Attributes["controls"]; exists {
		if !controlsAttr.IsOptional() {
			t.Error("Expected controls attribute to be optional")
		}
	}
}

func TestGithubChecksResource_Configure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		providerData  any
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid_client",
			providerData:  &stepsecurityapi.MockStepSecurityClient{},
			expectedError: false,
		},
		{
			name:          "nil_provider_data",
			providerData:  nil,
			expectedError: false,
		},
		{
			name:          "invalid_client_type",
			providerData:  "invalid",
			expectedError: true,
			errorContains: "Unexpected Data Source Configure Type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			ctx := context.Background()

			req := resource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			resp := &resource.ConfigureResponse{}

			r.Configure(ctx, req, resp)

			if tc.expectedError {
				if !resp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", resp.Diagnostics)
				}
			}
		})
	}
}

func TestGithubChecksResource_ValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		config        githubChecksModel
		expectedError bool
		errorContains string
	}{
		{
			name: "valid_config",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expectedError: false,
		},
		{
			name: "empty_owner",
			config: githubChecksModel{
				Owner: types.StringValue(""),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			expectedError: true,
			errorContains: "Owner is required",
		},
		{
			name: "empty_controls",
			config: githubChecksModel{
				Owner:    types.StringValue(testOwner),
				Controls: mustControlsList([]control{}),
			},
			expectedError: true,
			errorContains: "Controls are required",
		},
		{
			name: "invalid_control",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Invalid Control"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			expectedError: true,
			errorContains: "Invalid control provided",
		},
		{
			name: "invalid_type",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("invalid"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			expectedError: true,
			errorContains: "Type can only be 'required' or 'optional'",
		},
		{
			name: "cooldown_period_out_of_range",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(50); return &v }(), nil),
					},
				}),
			},
			expectedError: true,
			errorContains: "cool_down_period should be between 1 and 30",
		},
		{
			name: "valid_pypi_cooldown",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), nil),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expectedError: false,
		},
		{
			name: "valid_pypi_compromised_updates",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expectedError: false,
		},
		{
			name: "pypi_cooldown_period_out_of_range",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(50); return &v }(), nil),
					},
				}),
			},
			expectedError: true,
			errorContains: "cool_down_period should be between 1 and 30",
		},
		{
			name: "settings_provided_for_pypi_compromised_updates",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), nil),
					},
				}),
			},
			expectedError: true,
			errorContains: "can't provide settings",
		},
		{
			name: "valid_nuget_cooldown",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"MyCompany.Internal.Lib"}),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expectedError: false,
		},
		{
			name: "valid_nuget_compromised_updates",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expectedError: false,
		},
		{
			name: "nuget_cooldown_period_out_of_range",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(50); return &v }(), nil),
					},
				}),
			},
			expectedError: true,
			errorContains: "cool_down_period should be between 1 and 30",
		},
		{
			name: "settings_provided_for_nuget_compromised_updates",
			config: githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), nil),
					},
				}),
			},
			expectedError: true,
			errorContains: "can't provide settings",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &githubChecksResource{}

			resp := &resource.ValidateConfigResponse{}
			r.ValidateConfig(ctx, mustValidateConfigRequest(t, ctx, r, tc.config), resp)

			if tc.expectedError {
				if !resp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", resp.Diagnostics)
				}
			}
		})
	}
}

// TestGithubChecksResource_ValidateConfig_UnknownControlsList is a regression test for a
// customer-reported crash: when the whole "controls" list is unknown at plan time (e.g. it
// is derived from a for_each/local referencing a value that isn't known until apply), the
// framework used to fail to bind it into a plain []control field with:
//
//	"Received unknown value, however the target type cannot handle unknown values."
//
// ValidateConfig must handle this gracefully instead of erroring.
func TestGithubChecksResource_ValidateConfig_UnknownControlsList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &githubChecksResource{}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics)
	}

	model := githubChecksModel{
		Owner:          types.StringValue(testOwner),
		Controls:       types.ListUnknown(controlObjectType()),
		RequiredChecks: types.ObjectNull(checksConfigAttrTypes()),
		OptionalChecks: types.ObjectNull(checksConfigAttrTypes()),
		BaselineCheck:  types.ObjectNull(checksConfigAttrTypes()),
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, model)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics setting plan: %v", diags)
	}

	config := tfsdk.Config{Raw: plan.Raw, Schema: schemaResp.Schema}
	validateResp := &resource.ValidateConfigResponse{}

	assert.NotPanics(t, func() {
		r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: config}, validateResp)
	})
	assert.False(t, validateResp.Diagnostics.HasError(), "unexpected diagnostics: %v", validateResp.Diagnostics)
}

// TestGithubChecksResource_ValidateConfig_UnknownControlsListWithKnownRepos is a regression
// test for a false positive introduced while fixing the crash covered by
// TestGithubChecksResource_ValidateConfig_UnknownControlsList above: when "controls" is
// unknown but required_checks/baseline_check repos are known literals (e.g. "*", as in a
// customer config using terraform_data to make controls unknown on the first plan),
// ValidateConfig must not error with "can't provide repos for required checks without
// enabling any control for required checks". hasRequired/hasOptional cannot be determined
// while controls is unknown, so those cross-checks must be skipped until a later plan when
// controls becomes known.
func TestGithubChecksResource_ValidateConfig_UnknownControlsListWithKnownRepos(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &githubChecksResource{}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics)
	}

	starList, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building repos list: %v", diags)
	}

	model := githubChecksModel{
		Owner:    types.StringValue(testOwner),
		Controls: types.ListUnknown(controlObjectType()),
		RequiredChecks: mustChecksConfigObject(&checksConfig{
			Repos:     starList,
			OmitRepos: types.ListNull(types.StringType),
		}),
		OptionalChecks: types.ObjectNull(checksConfigAttrTypes()),
		BaselineCheck: mustChecksConfigObject(&checksConfig{
			Repos:     starList,
			OmitRepos: types.ListNull(types.StringType),
		}),
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	planDiags := plan.Set(ctx, model)
	if planDiags.HasError() {
		t.Fatalf("unexpected diagnostics setting plan: %v", planDiags)
	}

	config := tfsdk.Config{Raw: plan.Raw, Schema: schemaResp.Schema}
	validateResp := &resource.ValidateConfigResponse{}

	r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: config}, validateResp)

	assert.False(t, validateResp.Diagnostics.HasError(), "unexpected diagnostics (false positive on unknown controls + known repos): %v", validateResp.Diagnostics)
}

func TestGithubChecksResource_ConvertToCreateRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       githubChecksModel
		expected    stepsecurityapi.GitHubPRChecksConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "basic_config_with_npm_cooldown",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), nil),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(5),
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "package_exemptions",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"lodash", "express"}),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(3),
								"exempted_packages":       []string{"lodash", "express"},
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "multiple_controls_and_repos",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(7); return &v }(), nil),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{types.StringValue("repo1")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{
							types.StringValue("repo1"),
							types.StringValue("repo2"),
						}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(7),
							},
						},
						"script_injection_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"repo1": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: true,
					},
					"repo2": {
						Baseline:          false,
						RunRequiredChecks: true,
						RunOptionalChecks: true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "baseline_checks_enabled",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"script_injection_check": {
							Enabled:  true,
							Type:     "required",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := true; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "basic_config_with_pypi_cooldown",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"my-internal-pkg"}),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pypi_package_cooldown": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(3),
								"exempted_packages":       []string{"my-internal-pkg"},
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "pypi_compromised_updates",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pypi_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "nuget_cooldown_and_compromised_updates",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"MyCompany.Internal.Lib"}),
					},
					{
						Control:  types.StringValue("NuGet Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"nuget_package_cooldown": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(3),
								"exempted_packages":       []string{"MyCompany.Internal.Lib"},
							},
						},
						"nuget_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "omit_repos_configuration",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{
							types.StringValue("exclude-repo1"),
							types.StringValue("exclude-repo2"),
						}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pwn_request_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"exclude-repo1": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
					"exclude-repo2": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			result, err := r.convertToCreateRequest(context.Background(), tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Use Equal to compare the entire result structure
			assert.Equal(t, tc.expected, *result)
		})
	}
}

func TestGithubChecksResource_ConvertToState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		owner    string
		input    stepsecurityapi.GitHubPRChecksConfig
		expected githubChecksModel
	}{
		{
			name:  "basic_config_with_npm_cooldown",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(7),
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(7); return &v }(), nil),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				OptionalChecks: mustChecksConfigObject(nil),
				BaselineCheck:  mustChecksConfigObject(nil),
			},
		},
		{
			name:  "multiple_controls_with_settings",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(5),
								"exempted_packages": []string{
									"lodash",
									"express",
								},
							},
						},
						"pwn_request_check": {
							Enabled:  false,
							Type:     "required",
							Settings: map[string]any{},
						},
						"script_injection_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"repo1": {
						Baseline:          false,
						RunRequiredChecks: true,
						RunOptionalChecks: true,
					},
					"repo2": {
						Baseline:          true,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
				},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), []string{"lodash", "express"}),
					},
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(false),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{types.StringValue("repo2")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("repo1")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("repo2")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
			},
		},
		{
			name:  "all_global_flags_enabled",
			owner: "global-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := true; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("global-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
			},
		},
		{
			name:  "basic_config_with_pypi_cooldown",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pypi_package_cooldown": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(3),
								"exempted_packages":       []string{"my-internal-pkg"},
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"my-internal-pkg"}),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				OptionalChecks: mustChecksConfigObject(nil),
				BaselineCheck:  mustChecksConfigObject(nil),
			},
		},
		{
			name:  "pypi_compromised_updates",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pypi_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PyPI Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				OptionalChecks: mustChecksConfigObject(nil),
				BaselineCheck:  mustChecksConfigObject(nil),
			},
		},
		{
			// The API returns cooldown_period_in_days as a float64 after JSON decoding, so this
			// case also covers the float64 branch in convertToState.
			name:  "nuget_cooldown_and_compromised_updates",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"nuget_package_cooldown": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": float64(3),
								"exempted_packages":       []any{"MyCompany.Internal.Lib"},
							},
						},
						"nuget_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				// convertToState sorts controls by display name, so "Compromised Updates"
				// sorts before "Cooldown".
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NuGet Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("NuGet Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"MyCompany.Internal.Lib"}),
					},
				}),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				}),
				OptionalChecks: mustChecksConfigObject(nil),
				BaselineCheck:  mustChecksConfigObject(nil),
			},
		},
		{
			name:  "empty_config",
			owner: "empty-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks:                             map[string]stepsecurityapi.CheckConfig{},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner:          types.StringValue("empty-org"),
				Controls:       mustControlsList([]control{}),
				RequiredChecks: mustChecksConfigObject(nil),
				OptionalChecks: mustChecksConfigObject(nil),
				BaselineCheck:  mustChecksConfigObject(nil),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			got := r.convertToState(context.Background(), tc.owner, tc.input)

			// Use Equal to compare the entire result structure
			assert.Equal(t, tc.expected, got)
		})
	}
}

// Test configuration helpers
func testAccGithubChecksResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period = 5
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period = 10
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithBaseline(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "Script Injection"
      enable  = true
      type    = "required"
    }
  ]

  required_checks = {
    repos = ["*"]
  }

  baseline_check = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithPackageExemptions(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        packages_to_exempt_in_cooldown_check = ["lodash", "express"]
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithMultipleRepos(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "Script Injection"
      enable  = true
      type    = "required"
    },
    {
      control = "PWN Request"
      enable  = true
      type    = "optional"
    }
  ]

  required_checks = {
    repos = ["gh-actions-test-repo-2", "gh-actions-test-repo-1"]
  }

  optional_checks = {
    repos = ["gh-actions-test-repo-1", "gh-actions-test-repo-2"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithMultipleReposUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "Script Injection"
      enable  = true
      type    = "required"
    },
    {
      control = "PWN Request"
      enable  = true
      type    = "optional"
    }
  ]

  required_checks = {
    repos = ["gh-actions-test-repo-1", "gh-actions-test-repo-2"]
  }

  optional_checks = {
    repos = ["gh-actions-test-repo-1"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithOmitRepos(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period = 5
      }
    }
  ]

  required_checks = {
    repos       = ["*"]
    omit_repos  = ["gh-actions-test-repo-2", "gh-actions-test-repo-1"]
  }
}
`, owner)
}

// Unit tests for comparison functions
func TestGithubChecksResource_ListToStringSlice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		list     types.List
		expected []string
	}{
		{
			name: "non_empty_list",
			list: func() types.List {
				elements := []attr.Value{
					types.StringValue("repo1"),
					types.StringValue("repo2"),
					types.StringValue("repo3"),
				}
				list, _ := types.ListValue(types.StringType, elements)
				return list
			}(),
			expected: []string{"repo1", "repo2", "repo3"},
		},
		{
			name: "empty_list",
			list: func() types.List {
				elements := []attr.Value{}
				list, _ := types.ListValue(types.StringType, elements)
				return list
			}(),
			expected: []string{},
		},
		{
			name:     "null_list",
			list:     types.ListNull(types.StringType),
			expected: nil,
		},
		{
			name:     "unknown_list",
			list:     types.ListUnknown(types.StringType),
			expected: nil,
		},
		{
			name: "single_element",
			list: func() types.List {
				elements := []attr.Value{types.StringValue("*")}
				list, _ := types.ListValue(types.StringType, elements)
				return list
			}(),
			expected: []string{"*"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			got := r.listToStringSlice(tc.list)

			assert.Equal(t, tc.expected, got, "listToStringSlice() result mismatch")
		})
	}
}

func TestGithubChecksResource_UpdateStateListsWithOrderFromPlan(t *testing.T) {
	t.Parallel()

	// Helper function to create a list from strings
	createList := func(values []string) types.List {
		if values == nil {
			return types.ListNull(types.StringType)
		}
		elements := make([]attr.Value, len(values))
		for i, v := range values {
			elements[i] = types.StringValue(v)
		}
		list, _ := types.ListValue(types.StringType, elements)
		return list
	}

	testCases := []struct {
		name          string
		plan          githubChecksModel
		state         githubChecksModel
		expectedState githubChecksModel
	}{
		{
			name: "nil_state",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
			},
			state:         githubChecksModel{},
			expectedState: githubChecksModel{},
		},
		{
			name: "required_checks_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo1", "repo2", "repo3"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo3", "repo1", "repo2"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo1", "repo2", "repo3"}),
				}),
			},
		},
		{
			name: "required_checks_repos_different_content",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo1", "repo2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo3", "repo4"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo3", "repo4"}),
				}),
			},
		},
		{
			name: "required_checks_omit_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"exclude1", "exclude2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"exclude2", "exclude1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"exclude1", "exclude2"}),
				}),
			},
		},
		{
			name: "optional_checks_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt1", "opt2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt2", "opt1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt1", "opt2"}),
				}),
			},
		},
		{
			name: "optional_checks_omit_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"omit1", "omit2", "omit3"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"omit3", "omit2", "omit1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"omit1", "omit2", "omit3"}),
				}),
			},
		},
		{
			name: "baseline_check_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base1", "base2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base2", "base1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base1", "base2"}),
				}),
			},
		},
		{
			name: "baseline_check_omit_repos_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"skip1", "skip2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"skip2", "skip1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"*"}),
					OmitRepos: createList([]string{"skip1", "skip2"}),
				}),
			},
		},
		{
			name: "multiple_checks_all_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"req1", "req2"}),
					OmitRepos: createList([]string{"omit1", "omit2"}),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt1", "opt2"}),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base1", "base2"}),
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"req2", "req1"}),
					OmitRepos: createList([]string{"omit2", "omit1"}),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt2", "opt1"}),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base2", "base1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos:     createList([]string{"req1", "req2"}),
					OmitRepos: createList([]string{"omit1", "omit2"}),
				}),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt1", "opt2"}),
				}),
				BaselineCheck: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"base1", "base2"}),
				}),
			},
		},
		{
			name: "controls_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
		},
		{
			name: "controls_with_settings_same_content_different_order",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), []string{"lodash", "express"}),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), []string{"express", "lodash"}),
					},
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), []string{"express", "lodash"}),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
		},
		{
			name: "controls_missing_in_state",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: mustControlsList([]control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				}),
			},
		},
		{
			name: "plan_has_nil_required_checks_state_has_value",
			plan: githubChecksModel{
				Owner:          types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(nil),
			},
			state: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo1"}),
				}),
			},
			expectedState: githubChecksModel{
				Owner: types.StringValue("test-org"),
				RequiredChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"repo1"}),
				}),
			},
		},
		{
			name: "plan_has_value_state_has_nil_optional_checks",
			plan: githubChecksModel{
				Owner: types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(&checksConfig{
					Repos: createList([]string{"opt1"}),
				}),
			},
			state: githubChecksModel{
				Owner:          types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(nil),
			},
			expectedState: githubChecksModel{
				Owner:          types.StringValue("test-org"),
				OptionalChecks: mustChecksConfigObject(nil),
			},
		},
		{
			name: "empty_controls",
			plan: githubChecksModel{
				Owner:    types.StringValue("test-org"),
				Controls: mustControlsList([]control{}),
			},
			state: githubChecksModel{
				Owner:    types.StringValue("test-org"),
				Controls: mustControlsList([]control{}),
			},
			expectedState: githubChecksModel{
				Owner:    types.StringValue("test-org"),
				Controls: mustControlsList([]control{}),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			ctx := context.Background()

			// Make a copy of state to avoid modifying the test case
			stateCopy := tc.state

			r.updateStateListsWithOrderFromPlan(ctx, tc.plan, &stateCopy)

			// For controls, we need to manually check the order
			expectedControls := controlsListToSlice(tc.expectedState.Controls)
			actualControls := controlsListToSlice(stateCopy.Controls)
			if len(expectedControls) > 0 {
				assert.Equal(t, len(expectedControls), len(actualControls), "Controls length mismatch")
				for i := range expectedControls {
					assert.Equal(t, expectedControls[i].Control.ValueString(), actualControls[i].Control.ValueString(),
						"Control name mismatch at index %d", i)
					assert.Equal(t, expectedControls[i].Enable.ValueBool(), actualControls[i].Enable.ValueBool(),
						"Control enable mismatch at index %d", i)
					assert.Equal(t, expectedControls[i].Type.ValueString(), actualControls[i].Type.ValueString(),
						"Control type mismatch at index %d", i)
				}
			}

			// For lists, compare the string representation
			expectedRequiredChecks := checksConfigFromObject(tc.expectedState.RequiredChecks)
			actualRequiredChecks := checksConfigFromObject(stateCopy.RequiredChecks)
			if expectedRequiredChecks != nil && actualRequiredChecks != nil {
				assert.Equal(t, r.listToStringSlice(expectedRequiredChecks.Repos),
					r.listToStringSlice(actualRequiredChecks.Repos), "RequiredChecks.Repos mismatch")
				assert.Equal(t, r.listToStringSlice(expectedRequiredChecks.OmitRepos),
					r.listToStringSlice(actualRequiredChecks.OmitRepos), "RequiredChecks.OmitRepos mismatch")
			}

			expectedOptionalChecks := checksConfigFromObject(tc.expectedState.OptionalChecks)
			actualOptionalChecks := checksConfigFromObject(stateCopy.OptionalChecks)
			if expectedOptionalChecks != nil && actualOptionalChecks != nil {
				assert.Equal(t, r.listToStringSlice(expectedOptionalChecks.Repos),
					r.listToStringSlice(actualOptionalChecks.Repos), "OptionalChecks.Repos mismatch")
				assert.Equal(t, r.listToStringSlice(expectedOptionalChecks.OmitRepos),
					r.listToStringSlice(actualOptionalChecks.OmitRepos), "OptionalChecks.OmitRepos mismatch")
			}

			expectedBaselineCheck := checksConfigFromObject(tc.expectedState.BaselineCheck)
			actualBaselineCheck := checksConfigFromObject(stateCopy.BaselineCheck)
			if expectedBaselineCheck != nil && actualBaselineCheck != nil {
				assert.Equal(t, r.listToStringSlice(expectedBaselineCheck.Repos),
					r.listToStringSlice(actualBaselineCheck.Repos), "BaselineCheck.Repos mismatch")
				assert.Equal(t, r.listToStringSlice(expectedBaselineCheck.OmitRepos),
					r.listToStringSlice(actualBaselineCheck.OmitRepos), "BaselineCheck.OmitRepos mismatch")
			}
		})
	}
}
