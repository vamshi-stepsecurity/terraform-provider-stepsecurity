package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// hardenRunnerConfigObjectType mirrors the harden_runner_config attribute type used by
// the resource schema.
func hardenRunnerConfigObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"config":                        types.StringType,
		"update_existing_configuration": types.BoolType,
		"target_runner_labels":          types.ListType{ElemType: types.StringType},
		// A set, not a list: exempt patterns are an unordered exclusion set, so the
		// schema uses SetAttribute to keep ordering insignificant during plans.
		"exempt_runner_labels": types.SetType{ElemType: types.StringType},
	}}
}

func testStringList(t *testing.T, values ...string) types.List {
	t.Helper()
	list, diags := types.ListValueFrom(context.Background(), types.StringType, values)
	require.False(t, diags.HasError(), "building list: %v", diags)
	return list
}

func testStringSet(t *testing.T, values ...string) types.Set {
	t.Helper()
	set, diags := types.SetValueFrom(context.Background(), types.StringType, values)
	require.False(t, diags.HasError(), "building set: %v", diags)
	return set
}

func testHardenRunnerConfig(t *testing.T, labels ...string) types.Object {
	t.Helper()
	obj, diags := types.ObjectValue(
		hardenRunnerConfigObjectType().AttrTypes,
		map[string]attr.Value{
			"config":                        types.StringValue("egress-policy: audit"),
			"update_existing_configuration": types.BoolValue(false),
			"target_runner_labels":          testStringList(t, labels...),
			"exempt_runner_labels":          testStringSet(t),
		},
	)
	require.False(t, diags.HasError(), "building harden_runner_config: %v", diags)
	return obj
}

// readStateOptions decodes the auto_remediation_options object a read produced.
func readStateOptions(t *testing.T, state policyDrivenPRModel) autoRemdiationOptionsModel {
	t.Helper()
	var options autoRemdiationOptionsModel
	diags := state.AutoRemdiationOptions.As(context.Background(), &options, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError(), "decoding auto_remediation_options: %v", diags)
	return options
}

func listValues(t *testing.T, list types.List) []string {
	t.Helper()
	require.False(t, list.IsNull(), "expected a known list, got null")
	require.False(t, list.IsUnknown(), "expected a known list, got unknown")
	return listToStrings(list)
}

// TestReadPreservesConfiguredListOrder pins that a read leaves every order-insensitive
// list attribute in the order the practitioner configured it.
//
// The API stores actions_to_replace and update_precommit_file as JSON objects, so the
// read path derives those lists from a Go map range. GetPolicyDrivenPRPolicy sorts them
// so that two reads of a byte-identical response agree with each other (see #47/#78), but
// sorting alone is not enough: a configuration whose elements are not already in
// alphabetical order still gets a permanent reordering diff, because the sorted read
// never matches the configured order. The read has to realign to the prior state.
func TestReadPreservesConfiguredListOrder(t *testing.T) {
	ctx := context.Background()
	r := &policyDrivenPRResource{}

	// The practitioner's configured order, deliberately not alphabetical.
	configuredPrecommit := []string{"eslint", "gitleaks", "php-lint-all", "shellcheck", "trailing-whitespace", "end-of-file-fixer"}
	configuredReplace := []string{"actions/setup-node", "actions/checkout"}
	configuredExemptActions := []string{"zzz/action", "aaa/action"}
	configuredExemptImages := []string{"ubuntu:latest", "alpine:3.19"}
	configuredExemptedFromReplacement := []string{"my-org/keep-this", "another-org/keep-this-too"}
	configuredRunnerLabels := []string{"self-hosted-large", "self-hosted"}

	currentStateOptions := autoRemdiationOptionsModel{
		ActionsToExemptWhilePinning:             testStringList(t, configuredExemptActions...),
		ImagesToExemptWhilePinning:              testStringList(t, configuredExemptImages...),
		ActionsToReplaceWithStepSecurityActions: testStringList(t, configuredReplace...),
		ExemptedFromReplacement:                 testStringList(t, configuredExemptedFromReplacement...),
		UpdatePrecommitFile:                     testStringList(t, configuredPrecommit...),
		HardenRunnerConfig:                      testHardenRunnerConfig(t, configuredRunnerLabels...),
	}

	// What the API layer hands back: the same elements, sorted.
	apiPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: "test-org",
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			ActionsToExemptWhilePinning:             []string{"aaa/action", "zzz/action"},
			ImagesToExemptWhilePinning:              []string{"alpine:3.19", "ubuntu:latest"},
			ActionsToReplaceWithStepSecurityActions: []string{"actions/checkout", "actions/setup-node"},
			ExemptedFromReplacement:                 []string{"another-org/keep-this-too", "my-org/keep-this"},
			UpdatePrecommitFile:                     []string{"end-of-file-fixer", "eslint", "gitleaks", "php-lint-all", "shellcheck", "trailing-whitespace"},
			HardenRunnerConfig: &stepsecurityapi.HardenRunnerConfig{
				Config:       "egress-policy: audit",
				RunnerLabels: []string{"self-hosted", "self-hosted-large"},
			},
		},
		SelectedRepos: []string{"repo-a"},
	}

	var state policyDrivenPRModel
	r.updatePolicyDrivenPRState(ctx, apiPolicy, &state, []string{"repo-a"}, nil)
	r.preserveAutoRemediationListOrder(ctx, currentStateOptions, &state)

	options := readStateOptions(t, state)
	assert.Equal(t, configuredPrecommit, listValues(t, options.UpdatePrecommitFile), "update_precommit_file")
	assert.Equal(t, configuredReplace, listValues(t, options.ActionsToReplaceWithStepSecurityActions), "actions_to_replace_with_step_security_actions")
	assert.Equal(t, configuredExemptActions, listValues(t, options.ActionsToExemptWhilePinning), "actions_to_exempt_while_pinning")
	assert.Equal(t, configuredExemptImages, listValues(t, options.ImagesToExemptWhilePinning), "images_to_exempt_while_pinning")
	assert.Equal(t, configuredExemptedFromReplacement, listValues(t, options.ExemptedFromReplacement), "actions_exempted_from_replacement")

	var hardenRunner hardenRunnerConfigModel
	diags := options.HardenRunnerConfig.As(ctx, &hardenRunner, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError(), "decoding harden_runner_config: %v", diags)
	assert.Equal(t, configuredRunnerLabels, listValues(t, hardenRunner.RunnerLabels), "harden_runner_config.target_runner_labels")
}

// TestReadKeepsConfiguredOrderWhenMembershipChanges covers the case the previous
// same-elements-only reconciliation gave up on: when the live config genuinely differs
// from state, the elements that survive must still keep their configured positions, so
// the plan shows only the real add/remove rather than a wholesale reshuffle.
func TestReadKeepsConfiguredOrderWhenMembershipChanges(t *testing.T) {
	ctx := context.Background()
	r := &policyDrivenPRResource{}

	currentStateOptions := autoRemdiationOptionsModel{
		UpdatePrecommitFile: testStringList(t, "trailing-whitespace", "eslint", "gitleaks"),
	}

	apiPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: "test-org",
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			// "gitleaks" was removed out of band and "shellcheck" added; the rest is
			// what GetPolicyDrivenPRPolicy returns after sorting.
			UpdatePrecommitFile: []string{"eslint", "shellcheck", "trailing-whitespace"},
		},
		SelectedRepos: []string{"repo-a"},
	}

	var state policyDrivenPRModel
	r.updatePolicyDrivenPRState(ctx, apiPolicy, &state, []string{"repo-a"}, nil)
	r.preserveAutoRemediationListOrder(ctx, currentStateOptions, &state)

	options := readStateOptions(t, state)
	assert.Equal(t,
		[]string{"trailing-whitespace", "eslint", "shellcheck"},
		listValues(t, options.UpdatePrecommitFile),
		"survivors keep their configured order and the new element is appended")
}

// TestReadWithEmptyPriorStateLeavesApiOrder makes sure the realignment is inert when
// there is nothing to realign to, e.g. right after an import.
func TestReadWithEmptyPriorStateLeavesApiOrder(t *testing.T) {
	ctx := context.Background()
	r := &policyDrivenPRResource{}

	apiPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: "test-org",
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			UpdatePrecommitFile: []string{"eslint", "gitleaks"},
		},
		SelectedRepos: []string{"repo-a"},
	}

	var state policyDrivenPRModel
	r.updatePolicyDrivenPRState(ctx, apiPolicy, &state, []string{"repo-a"}, nil)
	r.preserveAutoRemediationListOrder(ctx, autoRemdiationOptionsModel{}, &state)

	options := readStateOptions(t, state)
	assert.Equal(t, []string{"eslint", "gitleaks"}, listValues(t, options.UpdatePrecommitFile))
}

// TestAlignListOrderHandlesDuplicates pins the multiset behaviour: a repeated element
// must not be dropped or multiplied by the realignment.
func TestAlignListOrderHandlesDuplicates(t *testing.T) {
	ctx := context.Background()

	stateList := testStringList(t, "b", "a", "b")
	apiList := testStringList(t, "a", "b", "b")

	aligned, changed := alignListOrder(ctx, stateList, apiList)
	require.True(t, changed)
	assert.Equal(t, []string{"b", "a", "b"}, listValues(t, aligned))
}

// TestReadMapsAbsentOptionalStringsToNull pins the null-vs-empty-string mapping for the
// Optional string attributes that have no default. The API omits them (omitempty), so Go
// decodes them to "", and writing that into state disagrees with a configuration that
// leaves them unset on every single refresh. Terraform then reports a change it renders as
// nothing at all: "Plan: 0 to add, 1 to change, 0 to destroy" with every attribute listed
// as unchanged.
func TestReadMapsAbsentOptionalStringsToNull(t *testing.T) {
	ctx := context.Background()
	r := &policyDrivenPRResource{}

	apiPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: "test-org",
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			PackageEcosystem: []stepsecurityapi.DependabotConfig{
				{Package: "npm", Interval: "daily"},
				{Package: "pip", Interval: "weekly", CoolDownYAML: "days: 7"},
			},
			HardenRunnerConfig: &stepsecurityapi.HardenRunnerConfig{},
		},
		SelectedRepos: []string{"repo-a"},
	}

	var state policyDrivenPRModel
	r.updatePolicyDrivenPRState(ctx, apiPolicy, &state, []string{"repo-a"}, nil)

	options := readStateOptions(t, state)

	var ecosystems []packageEcosystemModel
	diags := options.PackageEcosystem.ElementsAs(ctx, &ecosystems, false)
	require.False(t, diags.HasError(), "decoding package_ecosystem: %v", diags)
	require.Len(t, ecosystems, 2)

	assert.True(t, ecosystems[0].CoolDownYAML.IsNull(), "npm cooldown_yaml should be null, got %q", ecosystems[0].CoolDownYAML.ValueString())
	assert.True(t, ecosystems[0].GroupsYAML.IsNull(), "npm groups_yaml should be null, got %q", ecosystems[0].GroupsYAML.ValueString())
	assert.True(t, ecosystems[1].GroupsYAML.IsNull(), "pip groups_yaml should be null, got %q", ecosystems[1].GroupsYAML.ValueString())
	// A value the API does return must still come through untouched.
	assert.Equal(t, "days: 7", ecosystems[1].CoolDownYAML.ValueString(), "pip cooldown_yaml")

	var hardenRunner hardenRunnerConfigModel
	diags = options.HardenRunnerConfig.As(ctx, &hardenRunner, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError(), "decoding harden_runner_config: %v", diags)
	assert.True(t, hardenRunner.Config.IsNull(), "harden_runner_config.config should be null, got %q", hardenRunner.Config.ValueString())
}
