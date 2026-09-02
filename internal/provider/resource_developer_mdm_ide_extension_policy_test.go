package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func stringSet(t *testing.T, values ...string) types.Set {
	t.Helper()
	vals := make([]attr.Value, len(values))
	for i, v := range values {
		vals[i] = types.StringValue(v)
	}
	set, diags := types.SetValue(types.StringType, vals)
	require.False(t, diags.HasError())
	return set
}

// ideExtensionRulesList builds the framework list the model now carries. Calling it with no
// rules yields a known empty list, which is not the same as a null one.
func ideExtensionRulesList(t *testing.T, rules ...developerMDMIDEExtensionRuleModel) types.List {
	t.Helper()
	if rules == nil {
		rules = []developerMDMIDEExtensionRuleModel{}
	}
	value, diags := types.ListValueFrom(context.Background(), developerMDMIDEExtensionRuleObjectType(), rules)
	require.False(t, diags.HasError(), "rule conversion failed: %v", diags)
	return value
}

// ideExtensionRules decodes the model's rules list back into rule models for assertions.
func ideExtensionRules(t *testing.T, ctx context.Context, list types.List) []developerMDMIDEExtensionRuleModel {
	t.Helper()
	var rules []developerMDMIDEExtensionRuleModel
	diags := list.ElementsAs(ctx, &rules, false)
	require.False(t, diags.HasError(), "rule decoding failed: %v", diags)
	return rules
}

func TestDeveloperMDMIDEExtensionPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, name := range []string{"id", "policy_id", "name", "description", "target", "mode", "rules", "gallery_service_url", "created_by", "created_at", "updated_by", "updated_at"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestAllowlistStable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:        types.StringValue("eng"),
		Description: types.StringValue("approved extensions"),
		Target:      types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:        types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t, developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue("ms-python"),
			Name:      types.StringValue("python"),
			Versions:  types.SetNull(types.StringType),
			Stable:    types.BoolValue(true),
			Comment:   types.StringValue("approved per SEC-1234"),
		}),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError(), "build errors: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMCategoryIDEExtension, req.Category)
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetVSCode, req.Target)
	assert.Equal(t, 1, req.SpecVersion)
	assert.Equal(t, "allowlist", req.Mode)
	assert.Equal(t, "approved extensions", req.Description)

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, "ms-python", spec.Rules[0].Publisher)
	assert.True(t, spec.Rules[0].Stable)
	assert.Empty(t, spec.Rules[0].Versions)
	assert.Equal(t, "approved per SEC-1234", spec.Rules[0].Comment)
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestAllowlistVersions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:   types.StringValue("eng"),
		Target: types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:   types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t, developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue("redhat"),
			Name:      types.StringValue("vscode-yaml"),
			// Intentionally unsorted to verify deterministic ordering.
			Versions: stringSet(t, "2.0.0", "1.15.0", "1.10.0"),
			Stable:   types.BoolValue(false),
		}),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError())

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, []string{"1.10.0", "1.15.0", "2.0.0"}, spec.Rules[0].Versions)
	assert.False(t, spec.Rules[0].Stable)
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestBlocklist(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:   types.StringValue("block"),
		Target: types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:   types.StringValue("blocklist"),
		Rules: ideExtensionRulesList(t, developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue("evil"),
			Name:      types.StringValue("malware"),
			Versions:  types.SetNull(types.StringType),
			Stable:    types.BoolValue(false),
		}),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError())
	assert.Equal(t, "blocklist", req.Mode)

	// Blocklist rules carry no versions or stable; omitempty drops them from JSON.
	assert.NotContains(t, string(req.Spec), "versions")
	assert.NotContains(t, string(req.Spec), "stable")

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, "evil", spec.Rules[0].Publisher)
	assert.False(t, spec.Rules[0].Stable)
	assert.Empty(t, spec.Rules[0].Versions)
}

// TestDeveloperMDMIDEExtensionPolicy_BuildRequestPreservesRuleOrder pins the wire order of a
// multi-rule policy now that rules round-trip through a framework list. Order is part of the
// contract -- the backend compiles rules in sequence -- and a list preserves it where a set
// would not. It also checks that null optional fields still reach the API as zero values.
func TestDeveloperMDMIDEExtensionPolicy_BuildRequestPreservesRuleOrder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:   types.StringValue("eng"),
		Target: types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:   types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("zulu"), Name: types.StringValue("last"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("alpha"), Name: types.StringValue("first"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			// Every optional field null: they must reach the API as zero values.
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("mike"), Name: types.StringNull(), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(false), Comment: types.StringNull()},
		),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError(), "build errors: %v", diags)

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 3)

	// Declaration order, not sorted order.
	assert.Equal(t, []string{"zulu", "alpha", "mike"}, []string{spec.Rules[0].Publisher, spec.Rules[1].Publisher, spec.Rules[2].Publisher})

	assert.Empty(t, spec.Rules[2].Name)
	assert.Empty(t, spec.Rules[2].Versions)
	assert.Empty(t, spec.Rules[2].Comment)
	assert.False(t, spec.Rules[2].Stable)
}

func TestDeveloperMDMIDEExtensionPolicy_ValidateRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	rule := func(mut func(*developerMDMIDEExtensionRuleModel)) developerMDMIDEExtensionRuleModel {
		r := developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue("ms-python"),
			Name:      types.StringValue("python"),
			Versions:  types.SetNull(types.StringType),
			Stable:    types.BoolValue(false),
		}
		mut(&r)
		return r
	}

	cases := []struct {
		name string
		mode string
		rule developerMDMIDEExtensionRuleModel
	}{
		{"publisher with dot", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("ms.python") })},
		{"publisher wildcard", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("*") })},
		{"publisher with space", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("ms python") })},
		{"name wildcard", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Name = types.StringValue("py*thon") })},
		{"blocklist with versions", "blocklist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "1.0.0") })},
		{"versions without name", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) {
			r.Name = types.StringNull()
			r.Versions = stringSet(t, "1.0.0")
		})},
		{"bad version", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "1.0") })},
		{"literal stable version", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "stable") })},
		{"stable plus versions", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) {
			r.Stable = types.BoolValue(true)
			r.Versions = stringSet(t, "1.0.0")
		})},
		{"stable on blocklist", "blocklist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Stable = types.BoolValue(true) })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model := developerMDMIDEExtensionPolicyModel{
				Name:  types.StringValue("p"),
				Mode:  types.StringValue(tc.mode),
				Rules: ideExtensionRulesList(t, tc.rule),
			}
			diags := validateDeveloperMDMIDEExtensionPolicy(ctx, model)
			assert.True(t, diags.HasError(), "expected validation error for %q", tc.name)
		})
	}
}

func TestDeveloperMDMIDEExtensionPolicy_ValidateAcceptsValidRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Cross-rule conflict: same key cannot mix stable and explicit versions.
	conflict := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		),
	}
	assert.True(t, validateDeveloperMDMIDEExtensionPolicy(ctx, conflict).HasError(), "expected same-key stable/versions conflict")

	// versions with an unknown name defers rather than erroring: the name may
	// resolve to a valid value at apply time, and create/update re-validates
	// once it is known. (An explicitly null name still errors; see
	// TestDeveloperMDMIDEExtensionPolicy_ValidateRejectsInvalidRules.)
	unknownName := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringUnknown(), Versions: stringSet(t, "1.15.0"), Stable: types.BoolValue(false)},
		),
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, unknownName).HasError(), "versions with an unknown name should defer, not error")

	// An unknown-name versions rule must not falsely collide in the cross-rule
	// conflict map with a whole-publisher stable rule for the same publisher: the
	// compiled key is not known until the name resolves, so tracking defers rather
	// than treating the zero-value "" name as the same extension.
	unknownNameNoCollision := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("github"), Name: types.StringNull(), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("github"), Name: types.StringUnknown(), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		),
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, unknownNameNoCollision).HasError(), "unknown-name versions rule must not collide with a whole-publisher stable rule")

	// Empty rules are backend-valid for both modes, and a known empty list is not a null one.
	for _, mode := range []string{"allowlist", "blocklist"} {
		emptyRules := ideExtensionRulesList(t)
		assert.False(t, emptyRules.IsNull(), "an empty rules list must be known, not null")
		assert.False(t, emptyRules.IsUnknown(), "an empty rules list must be known, not unknown")
		assert.Empty(t, emptyRules.Elements())

		empty := developerMDMIDEExtensionPolicyModel{
			Name:  types.StringValue("p"),
			Mode:  types.StringValue(mode),
			Rules: emptyRules,
		}
		assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, empty).HasError(), "empty rules should be valid for %s", mode)
	}

	// Whole-publisher allow, stable allow, exact-version allow.
	valid := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("github"), Name: types.StringNull(), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(false)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("ms-python"), Name: types.StringValue("python"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringValue("vscode-yaml"), Versions: stringSet(t, "1.15.0", "1.15.0@linux-x64"), Stable: types.BoolValue(false)},
		),
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, valid).HasError(), "valid policy should not error: %v", validateDeveloperMDMIDEExtensionPolicy(ctx, valid))
}

// TestDeveloperMDMIDEExtensionPolicy_ConflictDiagnosticIsHumanReadable proves the
// cross-rule conflict message shows a readable `publisher.name` identifier and
// never leaks the internal NUL-delimited map key.
func TestDeveloperMDMIDEExtensionPolicy_ConflictDiagnosticIsHumanReadable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conflict := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t,
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		),
	}

	diags := validateDeveloperMDMIDEExtensionPolicy(ctx, conflict)
	require.True(t, diags.HasError(), "expected same-key stable/versions conflict")

	var detail string
	for _, d := range diags.Errors() {
		if strings.Contains(d.Summary(), "Conflicting rules") {
			detail = d.Detail()
		}
	}
	require.NotEmpty(t, detail, "expected a conflicting-rules diagnostic")
	assert.Contains(t, detail, "redhat.yaml", "message should use a human-readable publisher.name identifier")
	assert.NotContains(t, detail, "\x00", "message must not leak the internal NUL-delimited key")
}

// TestDeveloperMDMIDEExtensionPolicy_ValidateConfigDefersUnknownRules drives the real
// req.Config.Get path with the whole rules list unknown, which is the state a config that
// sources rules from a local, a module output, or another resource's computed attribute
// reaches on its first plan. It has to go through ValidateConfig rather than the validation
// helper alone: while the model held a Go slice, Get itself failed with "Received unknown
// value, however the target type cannot handle unknown values" before validation ever ran.
func TestDeveloperMDMIDEExtensionPolicy_ValidateConfigDefersUnknownRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceUnderTest := &developerMDMIDEExtensionPolicyResource{}

	schemaResp := &fwresource.SchemaResponse{}
	resourceUnderTest.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	model := developerMDMIDEExtensionPolicyModel{
		Name:              types.StringValue("eng"),
		Target:            types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:              types.StringValue(stepsecurityapi.DeveloperMDMModeAllowlist),
		Rules:             types.ListUnknown(developerMDMIDEExtensionRuleObjectType()),
		Description:       types.StringNull(),
		GalleryServiceURL: types.StringNull(),
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	require.False(t, plan.Set(ctx, model).HasError(), "setting plan failed")

	config := tfsdk.Config{Raw: plan.Raw, Schema: schemaResp.Schema}

	validateResp := &fwresource.ValidateConfigResponse{}
	resourceUnderTest.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, validateResp)

	assert.False(t, validateResp.Diagnostics.HasError(), "unknown rules should defer validation: %v", validateResp.Diagnostics)
}

// TestDeveloperMDMIDEExtensionPolicy_ValidateDefersUnknownRuleShapes covers the two list
// states that carry no rules to inspect. Neither may be read as an empty list: that would
// invent missing-name and duplicate-rule diagnostics out of values Terraform has not
// resolved. Each case also asserts that an unrelated known field is still validated, so
// deferring the rules does not quietly defer the whole resource.
func TestDeveloperMDMIDEExtensionPolicy_ValidateDefersUnknownRuleShapes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ruleType := developerMDMIDEExtensionRuleObjectType()

	unknownRuleObject, objDiags := types.ListValue(ruleType, []attr.Value{types.ObjectUnknown(ruleType.AttrTypes)})
	require.False(t, objDiags.HasError(), "building an unknown rule element failed: %v", objDiags)

	cases := map[string]types.List{
		"whole list unknown":  types.ListUnknown(ruleType),
		"unknown rule object": unknownRuleObject,
	}

	for name, rules := range cases {
		rules := rules
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			model := developerMDMIDEExtensionPolicyModel{
				Name:  types.StringValue("p"),
				Mode:  types.StringValue("allowlist"),
				Rules: rules,
			}
			assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, model).HasError(),
				"rules that are not structurally known should defer: %v", validateDeveloperMDMIDEExtensionPolicy(ctx, model))

			model.GalleryServiceURL = types.StringValue("http://gallery.example.com/gallery")
			assert.True(t, validateDeveloperMDMIDEExtensionPolicy(ctx, model).HasError(),
				"a known-bad gallery URL must still be reported while rules are deferred")
		})
	}
}

// TestDeveloperMDMIDEExtensionPolicy_ValidateDefersUnknownRuleFields keeps attribute-level
// deferral intact now that rules travel as a list. A known rule object whose every field is
// unknown still decodes, and nothing about it can be judged until the fields resolve.
func TestDeveloperMDMIDEExtensionPolicy_ValidateDefersUnknownRuleFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: ideExtensionRulesList(t, developerMDMIDEExtensionRuleModel{
			Publisher: types.StringUnknown(),
			Name:      types.StringUnknown(),
			Versions:  types.SetUnknown(types.StringType),
			Stable:    types.BoolUnknown(),
			Comment:   types.StringUnknown(),
		}),
	}

	diags := validateDeveloperMDMIDEExtensionPolicy(ctx, model)
	assert.False(t, diags.HasError(), "an all-unknown rule should defer, not error: %v", diags)
}

// TestDeveloperMDMIDEExtensionRuleObjectType_MatchesSchema keeps the canonical rule element
// type from drifting away from the nested schema. A mismatch still compiles; it surfaces at
// runtime as an opaque conversion error on every read.
func TestDeveloperMDMIDEExtensionRuleObjectType_MatchesSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	rules, ok := schemaResp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok, "rules should be a ListNestedAttribute")

	want := developerMDMIDEExtensionRuleObjectType()
	assert.True(t, want.Equal(rules.NestedObject.Type()),
		"rule object type %s does not match the nested schema %s", want, rules.NestedObject.Type())
}

// TestDeveloperMDMIDEExtensionPolicy_BuildRequestRejectsUnknownRules proves the builder
// refuses to ship rules it cannot see. Terraform resolves a required attribute before create
// or update, so this is unreachable today; it exists so a future lifecycle change fails
// loudly instead of sending an empty rule list, which on an allowlist blocks every extension.
func TestDeveloperMDMIDEExtensionPolicy_BuildRequestRejectsUnknownRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:  types.StringValue("eng"),
		Mode:  types.StringValue("allowlist"),
		Rules: types.ListUnknown(developerMDMIDEExtensionRuleObjectType()),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.True(t, diags.HasError(), "unknown rules must not become an empty API rule list")
	assert.Empty(t, req.Spec, "no spec should be built from unknown rules")
}

func TestDeveloperMDMIDEExtensionPolicy_ApplyAPIToModel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID:    "p1",
		Name:        "eng",
		Description: "desc",
		Category:    "ide_extension",
		Target:      "vscode",
		Mode:        "allowlist",
		SpecVersion: 1,
		Spec:        json.RawMessage(`{"rules":[{"publisher":"ms-python","name":"python","stable":true,"comment":"approved per SEC-1234"},{"publisher":"redhat","name":"vscode-yaml","versions":["1.15.0"]}]}`),
		CreatedBy:   "user@x.io",
		CreatedAt:   "2026-06-29T00:00:00Z",
		UpdatedBy:   "user@x.io",
		UpdatedAt:   "2026-06-29T01:00:00Z",
	}

	model := &developerMDMIDEExtensionPolicyModel{}
	var diags diag.Diagnostics
	applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
	require.False(t, diags.HasError(), "apply errors: %v", diags)

	assert.Equal(t, "p1", model.ID.ValueString())
	assert.Equal(t, "p1", model.PolicyID.ValueString())
	assert.Equal(t, "eng", model.Name.ValueString())
	assert.Equal(t, "vscode", model.Target.ValueString())
	assert.Equal(t, "desc", model.Description.ValueString())
	assert.Equal(t, "allowlist", model.Mode.ValueString())
	assert.Equal(t, "user@x.io", model.CreatedBy.ValueString())
	assert.Equal(t, "2026-06-29T01:00:00Z", model.UpdatedAt.ValueString())

	// An API response always yields a known list; only a config expression can be unknown.
	assert.False(t, model.Rules.IsNull(), "rules from an API response must be known")
	assert.False(t, model.Rules.IsUnknown(), "rules from an API response must be known")

	rules := ideExtensionRules(t, ctx, model.Rules)
	require.Len(t, rules, 2)
	// Order follows the API response, not a sort.
	assert.Equal(t, "ms-python", rules[0].Publisher.ValueString())
	assert.True(t, rules[0].Stable.ValueBool())
	assert.True(t, rules[0].Versions.IsNull())
	assert.Equal(t, "approved per SEC-1234", rules[0].Comment.ValueString())
	assert.Equal(t, "redhat", rules[1].Publisher.ValueString())
	// Rule 1 carries no comment in the API response, so it reads back as null.
	assert.True(t, rules[1].Comment.IsNull())

	var versions []string
	rules[1].Versions.ElementsAs(ctx, &versions, false)
	assert.Equal(t, []string{"1.15.0"}, versions)
}

// TestDeveloperMDMIDEExtensionPolicy_ApplyEmptyRulesIsKnownEmptyList pins the distinction
// the framework list makes possible. A policy with no rules must read back as `rules = []`,
// not `rules = null`: an empty allowlist blocks every extension, so null would both be a
// lie and provoke a permanent diff against a config that writes `rules = []`.
func TestDeveloperMDMIDEExtensionPolicy_ApplyEmptyRulesIsKnownEmptyList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, spec := range []string{`{"rules":[]}`, `{}`} {
		t.Run(spec, func(t *testing.T) {
			t.Parallel()
			policy := &stepsecurityapi.DeveloperMDMPolicy{
				PolicyID: "p1",
				Name:     "eng",
				Category: "ide_extension",
				Target:   "vscode",
				Mode:     "allowlist",
				Spec:     json.RawMessage(spec),
			}

			model := &developerMDMIDEExtensionPolicyModel{}
			var diags diag.Diagnostics
			applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
			require.False(t, diags.HasError(), "apply errors: %v", diags)

			assert.False(t, model.Rules.IsNull(), "no rules must be a known empty list, not null")
			assert.False(t, model.Rules.IsUnknown())
			assert.Empty(t, model.Rules.Elements())
		})
	}
}

// TestDeveloperMDMIDEExtensionPolicy_BuildRequestGalleryServiceURL pins the wire shape of
// an unset marketplace URL. An unset attribute reaches the builder as null and stringifies
// to "", so only omitempty keeps a URL-less policy storing the same spec it stored before
// the field existed.
func TestDeveloperMDMIDEExtensionPolicy_BuildRequestGalleryServiceURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := func(url types.String) developerMDMIDEExtensionPolicyModel {
		return developerMDMIDEExtensionPolicyModel{
			Name:              types.StringValue("eng"),
			Target:            types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
			Mode:              types.StringValue("allowlist"),
			GalleryServiceURL: url,
			Rules: ideExtensionRulesList(t, developerMDMIDEExtensionRuleModel{
				Publisher: types.StringValue("ms-python"),
				Name:      types.StringValue("python"),
				Versions:  types.SetNull(types.StringType),
				Stable:    types.BoolValue(true),
			}),
		}
	}

	t.Run("unset omits the key", func(t *testing.T) {
		t.Parallel()
		var diags diag.Diagnostics
		req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, base(types.StringNull()), &diags)
		require.False(t, diags.HasError(), "build errors: %v", diags)

		assert.NotContains(t, string(req.Spec), "gallery_service_url")

		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(req.Spec, &raw))
		assert.NotContains(t, raw, "gallery_service_url")
	})

	t.Run("set is sent verbatim", func(t *testing.T) {
		t.Parallel()
		const wantURL = "https://gallery.example.com/_apis/public/gallery"

		var diags diag.Diagnostics
		req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, base(types.StringValue(wantURL)), &diags)
		require.False(t, diags.HasError(), "build errors: %v", diags)

		var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
		require.NoError(t, json.Unmarshal(req.Spec, &spec))
		assert.Equal(t, wantURL, spec.GalleryServiceURL)
	})
}

func TestValidateGalleryServiceURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		raw       string
		wantError bool
	}{
		{"valid https URL", "https://gallery.example.com/_apis/public/gallery", false},
		{"scheme match is case-insensitive", "HTTPS://gallery.example.com/gallery", false},
		{"space inside the path is allowed", "https://gallery.example.com/a b", false},
		{"http scheme", "http://gallery.example.com/gallery", true},
		{"missing host", "https:///gallery", true},
		{"userinfo", "https://user:pass@gallery.example.com/gallery", true},
		{"fragment", "https://gallery.example.com/gallery#frag", true},
		{"bare hash", "https://gallery.example.com/gallery#", true},
		{"leading space", " https://gallery.example.com/gallery", true},
		{"control byte", "https://gallery.example.com/gal\x01lery", true},
		// Reaches url.Parse's error branch: it passes every earlier check and fails to
		// parse. The control-byte row cannot cover it, because the control-character loop
		// runs first and intercepts those inputs.
		{"unparseable escape", "https://example.com/%zz", true},
		{"too long", "https://gallery.example.com/" + strings.Repeat("a", 2049), true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			summary, detail := validateGalleryServiceURL(tc.raw)
			if tc.wantError {
				assert.NotEmpty(t, summary, "expected %q to be rejected", tc.raw)
				assert.NotEmpty(t, detail, "a rejection should explain itself")
				return
			}
			assert.Empty(t, summary, "expected %q to be accepted, got: %s", tc.raw, detail)
		})
	}
}

func TestDeveloperMDMIDEExtensionPolicy_ApplyGalleryServiceURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const wantURL = "https://gallery.example.com/_apis/public/gallery"

	cases := []struct {
		name     string
		spec     string
		wantNull bool
	}{
		{"URL round-trips", `{"rules":[],"gallery_service_url":"` + wantURL + `"}`, false},
		{"absent URL becomes null", `{"rules":[]}`, true},
		{"empty URL becomes null", `{"rules":[],"gallery_service_url":""}`, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policy := &stepsecurityapi.DeveloperMDMPolicy{
				PolicyID: "p1",
				Name:     "eng",
				Category: "ide_extension",
				Target:   "vscode",
				Mode:     "allowlist",
				Spec:     json.RawMessage(tc.spec),
			}

			model := &developerMDMIDEExtensionPolicyModel{}
			var diags diag.Diagnostics
			applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
			require.False(t, diags.HasError(), "apply errors: %v", diags)

			assert.Equal(t, tc.wantNull, model.GalleryServiceURL.IsNull())
			if !tc.wantNull {
				assert.Equal(t, wantURL, model.GalleryServiceURL.ValueString())
			}
		})
	}
}

func TestDeveloperMDMIDEExtensionPolicy_ValidateGalleryServiceURLIsModeIndependent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, mode := range []string{stepsecurityapi.DeveloperMDMModeAllowlist, stepsecurityapi.DeveloperMDMModeBlocklist} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			model := developerMDMIDEExtensionPolicyModel{
				Name:              types.StringValue("eng"),
				Mode:              types.StringValue(mode),
				GalleryServiceURL: types.StringValue("https://gallery.example.com/_apis/public/gallery"),
				Rules: ideExtensionRulesList(t,
					developerMDMIDEExtensionRuleModel{Publisher: types.StringValue("github"), Versions: types.SetNull(types.StringType)},
				),
			}

			diags := validateDeveloperMDMIDEExtensionPolicy(ctx, model)
			assert.False(t, diags.HasError(), "a marketplace URL should be valid on a %s: %v", mode, diags)
		})
	}
}

// TestDeveloperMDMIDEExtensionPolicy_GalleryServiceURLRejectsEmpty exercises the schema
// validator on `gallery_service_url`. An unset marketplace is expressed by omitting the
// attribute, not by ""; an empty string would be dropped by omitempty and read back as
// null, causing an apply inconsistency, so it is rejected at plan time.
func TestDeveloperMDMIDEExtensionPolicy_GalleryServiceURLRejectsEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	urlAttr, ok := schemaResp.Schema.Attributes["gallery_service_url"].(schema.StringAttribute)
	require.True(t, ok, "gallery_service_url should be a StringAttribute")
	require.NotEmpty(t, urlAttr.Validators, "gallery_service_url should have length validators")

	validate := func(value string) diag.Diagnostics {
		var all diag.Diagnostics
		for _, v := range urlAttr.Validators {
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("gallery_service_url"),
				ConfigValue: types.StringValue(value),
			}, resp)
			all.Append(resp.Diagnostics...)
		}
		return all
	}

	assert.True(t, validate("").HasError(), "empty URL should be rejected (omit the attribute instead)")
	assert.False(t, validate("https://gallery.example.com/gallery").HasError(), "a real URL should be accepted")
	assert.True(t, validate("https://gallery.example.com/"+strings.Repeat("a", 2049)).HasError(), "over the 2048 cap should be rejected")
}

// TestDeveloperMDMIDEExtensionPolicy_CommentLengthValidator exercises the schema
// validator wired to the rule `comment` attribute. The imperative
// validateDeveloperMDMIDEExtensionPolicy helper does not run schema-level
// validators, so the bounds are verified by pulling the validator off the schema
// and running it directly. Empty is rejected (an unset comment is expressed by
// omitting the attribute, not by ""; this avoids an apply inconsistency from the
// omitempty round-trip). The multibyte case confirms the cap counts runes, not
// bytes (i.e. a UTF8-length validator, not a byte-length one).
func TestDeveloperMDMIDEExtensionPolicy_CommentLengthValidator(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	rules, ok := schemaResp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok, "rules should be a ListNestedAttribute")
	comment, ok := rules.NestedObject.Attributes["comment"].(schema.StringAttribute)
	require.True(t, ok, "comment should be a StringAttribute")
	require.NotEmpty(t, comment.Validators, "comment should have a length validator")

	validate := func(value string) diag.Diagnostics {
		var all diag.Diagnostics
		for _, v := range comment.Validators {
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("rules").AtListIndex(0).AtName("comment"),
				ConfigValue: types.StringValue(value),
			}, resp)
			all.Append(resp.Diagnostics...)
		}
		return all
	}

	assert.True(t, validate("").HasError(), "empty comment should be rejected (omit the attribute instead)")
	assert.False(t, validate(strings.Repeat("a", 512)).HasError(), "512 runes should be accepted")
	assert.True(t, validate(strings.Repeat("a", 513)).HasError(), "513 runes should be rejected")
	assert.False(t, validate(strings.Repeat("世", 512)).HasError(), "512 multibyte runes should be accepted (rune-counted)")
}

// TestDeveloperMDMIDEExtensionPolicy_RuleNameRejectsEmpty exercises the schema
// validator on the rule `name` attribute. An unset name (target the whole
// publisher) is expressed by omitting the attribute, not by ""; an empty string
// would be dropped by omitempty and read back as null, causing an apply
// inconsistency, so it is rejected at plan time.
func TestDeveloperMDMIDEExtensionPolicy_RuleNameRejectsEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	rules, ok := schemaResp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok, "rules should be a ListNestedAttribute")
	nameAttr, ok := rules.NestedObject.Attributes["name"].(schema.StringAttribute)
	require.True(t, ok, "name should be a StringAttribute")
	require.NotEmpty(t, nameAttr.Validators, "name should have a length validator")

	validate := func(value string) diag.Diagnostics {
		var all diag.Diagnostics
		for _, v := range nameAttr.Validators {
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("rules").AtListIndex(0).AtName("name"),
				ConfigValue: types.StringValue(value),
			}, resp)
			all.Append(resp.Diagnostics...)
		}
		return all
	}

	assert.True(t, validate("").HasError(), "empty name should be rejected (omit the attribute to target the whole publisher)")
	assert.False(t, validate("python").HasError(), "a non-empty name should be accepted")
}

func TestDeveloperMDMIDEExtensionPolicy_NonIDECategoryReadDiagnostic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "p1",
		Name:     "other",
		Category: "some_other_category",
		Mode:     "allowlist",
	}

	model := &developerMDMIDEExtensionPolicyModel{}
	var diags diag.Diagnostics
	applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
	assert.True(t, diags.HasError(), "expected diagnostic for non-ide_extension category")
}

// TestAccDeveloperMDMIDEExtensionPolicyResource runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccDeveloperMDMIDEExtensionPolicyResource(t *testing.T) {
	const name = "tf-acc IDE extension policy"
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create.
			{
				Config: testAccDeveloperMDMIDEExtensionPolicyConfig(name, "approved extensions", "true"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "name", name),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "mode", "allowlist"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "description", "approved extensions"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "rules.0.comment", "approved for engineering"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_developer_mdm_ide_extension_policy.test", "policy_id"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_developer_mdm_ide_extension_policy.test", "id"),
				),
			},
			// Import by policy_id.
			{
				ResourceName:      "stepsecurity_developer_mdm_ide_extension_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update description and a rule field.
			{
				Config: testAccDeveloperMDMIDEExtensionPolicyConfig(name, "updated description", "false"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "description", "updated description"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "rules.0.stable", "false"),
				),
			},
		},
	})
}

func testAccDeveloperMDMIDEExtensionPolicyConfig(name, description, stable string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_developer_mdm_ide_extension_policy" "test" {
  name        = %q
  description = %q
  mode        = "allowlist"

  rules = [
    {
      publisher = "ms-python"
      name      = "python"
      stable    = %s
      comment   = "approved for engineering"
    },
  ]
}
`, name, description, stable)
}
