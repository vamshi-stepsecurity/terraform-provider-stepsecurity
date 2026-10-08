package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// packageConfigSchema returns the resource's real schema, which every configuration and
// planning test below builds its tfsdk values from.
func packageConfigSchema(t *testing.T) schema.Schema {
	t.Helper()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMPackageConfigPolicyResource().Schema(context.Background(), fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "Schema() errors: %v", schemaResp.Diagnostics)
	return schemaResp.Schema
}

// packageConfigModel builds a valid npm policy and applies the given mutations.
func packageConfigModel(mutators ...func(*developerMDMPackageConfigPolicyModel)) developerMDMPackageConfigPolicyModel {
	model := developerMDMPackageConfigPolicyModel{
		ID:           types.StringNull(),
		PolicyID:     types.StringNull(),
		Name:         types.StringValue("packages"),
		Description:  types.StringNull(),
		Target:       types.StringValue(stepsecurityapi.DeveloperMDMTargetNPM),
		RegistryType: types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity),
		Settings:     types.MapNull(types.StringType),
		Clients:      types.SetNull(types.StringType),
		CreatedBy:    types.StringNull(),
		CreatedAt:    types.StringNull(),
		UpdatedBy:    types.StringNull(),
		UpdatedAt:    types.StringNull(),
	}
	for _, mutate := range mutators {
		mutate(&model)
	}
	return model
}

// packageConfigValidateConfig drives the real ValidateConfig entry point through
// tfsdk.Config.Get rather than calling the validation helper with a preconstructed model.
// That path is the point of these tests: while the IDE extension model held a Go slice, Get
// itself failed on a wholly unknown collection before any validation ran (commit c236a3f),
// and a helper-level test could not have caught it.
func packageConfigValidateConfig(t *testing.T, model developerMDMPackageConfigPolicyModel) diag.Diagnostics {
	t.Helper()
	ctx := context.Background()
	resourceUnderTest := &developerMDMPackageConfigPolicyResource{}
	resourceSchema := packageConfigSchema(t)

	plan := tfsdk.Plan{Schema: resourceSchema}
	require.False(t, plan.Set(ctx, model).HasError(), "setting plan failed")
	config := tfsdk.Config{Raw: plan.Raw, Schema: resourceSchema}

	resp := &fwresource.ValidateConfigResponse{}
	resourceUnderTest.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, resp)
	return resp.Diagnostics
}

func packageConfigSettings(t *testing.T, entries map[string]attr.Value) types.Map {
	t.Helper()
	value, diags := types.MapValue(types.StringType, entries)
	require.False(t, diags.HasError(), "building settings failed: %v", diags)
	return value
}

func packageConfigStringSettings(t *testing.T, entries map[string]string) types.Map {
	t.Helper()
	values := make(map[string]attr.Value, len(entries))
	for key, value := range entries {
		values[key] = types.StringValue(value)
	}
	return packageConfigSettings(t, values)
}

func diagSummaries(diags diag.Diagnostics) []string {
	summaries := make([]string, 0, diags.ErrorsCount())
	for _, d := range diags.Errors() {
		summaries = append(summaries, d.Summary())
	}
	return summaries
}

func assertHasSummary(t *testing.T, diags diag.Diagnostics, summary string) {
	t.Helper()
	assert.Contains(t, diagSummaries(diags), summary, "diagnostics: %v", diags)
}

func TestDeveloperMDMPackageConfigPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	attrs := packageConfigSchema(t).Attributes
	for _, name := range []string{"id", "policy_id", "name", "description", "target", "registry_type", "settings", "clients", "created_by", "created_at", "updated_by", "updated_at"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
	// package_config has no user-facing mode or rules, unlike ide_extension.
	assert.NotContains(t, attrs, "mode")
	assert.NotContains(t, attrs, "rules")

	// The API rejects changing a policy's target in place, so the plan must show a replace.
	target, ok := attrs["target"].(schema.StringAttribute)
	require.True(t, ok, "target should be a string attribute")
	assert.NotEmpty(t, target.PlanModifiers, "target must carry RequiresReplace")

	// UseStateForUnknown on the selector would substitute the prior value for an
	// unresolved configured one, hiding a real change. It must stay off.
	registryType, ok := attrs["registry_type"].(schema.StringAttribute)
	require.True(t, ok, "registry_type should be a string attribute")
	assert.Empty(t, registryType.PlanModifiers, "registry_type must not carry a plan modifier, in particular not UseStateForUnknown")
}

// TestDeveloperMDMPackageConfigPolicy_RegistryDefaultIsUnconditional pins the framework
// default itself: it resolves to stepsecurity with no reference to settings, which is what
// keeps an existing npm policy on the StepSecurity registry when a customer adds settings.
func TestDeveloperMDMPackageConfigPolicy_RegistryDefaultIsUnconditional(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registryType, ok := packageConfigSchema(t).Attributes["registry_type"].(schema.StringAttribute)
	require.True(t, ok)
	require.NotNil(t, registryType.Default, "registry_type must keep its static default")

	resp := &defaults.StringResponse{}
	registryType.Default.DefaultString(ctx, defaults.StringRequest{Path: path.Root("registry_type")}, resp)
	require.False(t, resp.Diagnostics.HasError(), "default errors: %v", resp.Diagnostics)
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, resp.PlanValue.ValueString())
}

func TestDeveloperMDMPackageConfigPolicy_BuildRequestDefaults(t *testing.T) {
	t.Parallel()

	model := packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.Name = types.StringValue("npm secure registry")
		m.Description = types.StringValue("route installs through StepSecurity")
		// target and registry_type omitted: builder must default them.
		m.Target = types.StringNull()
		m.RegistryType = types.StringNull()
	})

	var diags diag.Diagnostics
	req := buildDeveloperMDMPackageConfigPolicyRequest(context.Background(), model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, "npm secure registry", req.Name)
	assert.Equal(t, "route installs through StepSecurity", req.Description)
	assert.Equal(t, stepsecurityapi.DeveloperMDMCategoryPackageConfig, req.Category)
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, req.Target)
	assert.Equal(t, stepsecurityapi.DeveloperMDMSpecVersionPackageConfig, req.SpecVersion)
	assert.Equal(t, stepsecurityapi.DeveloperMDMModeAllowlist, req.Mode)

	// Byte-compatible with the spec the resource shipped before settings existed: the
	// production API still validates exactly this shape.
	assert.JSONEq(t, `{"registry":{"type":"stepsecurity"}}`, string(req.Spec))
}

func TestDeveloperMDMPackageConfigPolicy_BuildRequestExplicitValues(t *testing.T) {
	t.Parallel()

	model := packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.Name = types.StringValue("npm")
	})

	var diags diag.Diagnostics
	req := buildDeveloperMDMPackageConfigPolicyRequest(context.Background(), model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, req.Target)
	assert.JSONEq(t, `{"registry":{"type":"stepsecurity"}}`, string(req.Spec))
}

// TestDeveloperMDMPackageConfigPolicy_BuildRequestShapes covers every wire shape the
// resource can produce. The combined npm row is the compatibility promise: adding settings
// with an omitted selector keeps the StepSecurity registry rather than silently dropping it.
func TestDeveloperMDMPackageConfigPolicy_BuildRequestShapes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate func(*developerMDMPackageConfigPolicyModel)
		spec   string
	}{
		"npm settings with omitted selector keeps stepsecurity": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.RegistryType = types.StringNull()
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})
			},
			spec: `{"registry":{"type":"stepsecurity"},"settings":{"fetch-retries":"3"}}`,
		},
		"npm settings with explicit stepsecurity": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})
			},
			spec: `{"registry":{"type":"stepsecurity"},"settings":{"fetch-retries":"3"}}`,
		},
		"npm settings only omits the registry entirely": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
				m.Settings = packageConfigStringSettings(t, map[string]string{
					"registry":         "https://registry.example.com/npm/",
					"fetch-retries":    "3",
					"empty-on-purpose": "",
				})
			},
			spec: `{"settings":{"registry":"https://registry.example.com/npm/","fetch-retries":"3","empty-on-purpose":""}}`,
		},
		"pypi carries clients and no settings": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
				m.Clients = stringSet(t, "uv", "pip")
			},
			spec: `{"registry":{"type":"stepsecurity"},"clients":["pip","uv"]}`,
		},
		"go carries the registry alone": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetGo)
				m.RegistryType = types.StringNull()
			},
			spec: `{"registry":{"type":"stepsecurity"}}`,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			req := buildDeveloperMDMPackageConfigPolicyRequest(context.Background(), packageConfigModel(tc.mutate), &diags)
			require.False(t, diags.HasError(), "unexpected diags: %v", diags)
			assert.JSONEq(t, tc.spec, string(req.Spec))
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_BuildRequestClientOrderIsStable pins the serialized
// client order: the set makes ordering invisible to Terraform, so only the request path can
// guarantee the API receives a stable array.
func TestDeveloperMDMPackageConfigPolicy_BuildRequestClientOrderIsStable(t *testing.T) {
	t.Parallel()

	for _, clients := range [][]string{{"pip", "uv"}, {"uv", "pip"}} {
		clients := clients
		var diags diag.Diagnostics
		req := buildDeveloperMDMPackageConfigPolicyRequest(context.Background(), packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
			m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
			m.Clients = stringSet(t, clients...)
		}), &diags)
		require.False(t, diags.HasError(), "unexpected diags: %v", diags)

		var spec stepsecurityapi.DeveloperMDMPackageConfigSpec
		require.NoError(t, json.Unmarshal(req.Spec, &spec))
		assert.Equal(t, []string{"pip", "uv"}, spec.Clients, "input order %v must serialize identically", clients)
	}
}

// TestDeveloperMDMPackageConfigPolicy_BuildRequestRefusesUnresolved makes sure an unresolved
// authoring value is diagnosed rather than read as a default or an empty collection, which
// would ship a spec the user never wrote.
func TestDeveloperMDMPackageConfigPolicy_BuildRequestRefusesUnresolved(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*developerMDMPackageConfigPolicyModel){
		"unknown target": func(m *developerMDMPackageConfigPolicyModel) {
			m.Target = types.StringUnknown()
		},
		"unknown selector": func(m *developerMDMPackageConfigPolicyModel) {
			m.RegistryType = types.StringUnknown()
		},
		"unknown settings map": func(m *developerMDMPackageConfigPolicyModel) {
			m.Settings = types.MapUnknown(types.StringType)
		},
		"unknown settings value": func(m *developerMDMPackageConfigPolicyModel) {
			m.Settings = packageConfigSettings(t, map[string]attr.Value{"registry": types.StringUnknown()})
		},
		"unknown clients set": func(m *developerMDMPackageConfigPolicyModel) {
			m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
			m.Clients = types.SetUnknown(types.StringType)
		},
		"unknown clients element": func(m *developerMDMPackageConfigPolicyModel) {
			m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
			set, diags := types.SetValue(types.StringType, []attr.Value{types.StringValue("pip"), types.StringUnknown()})
			require.False(t, diags.HasError(), "%v", diags)
			m.Clients = set
		},
	}

	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			req := buildDeveloperMDMPackageConfigPolicyRequest(context.Background(), packageConfigModel(mutate), &diags)
			require.True(t, diags.HasError(), "expected an unresolved-value diagnostic")
			assertHasSummary(t, diags, "Value is not fully known")
			assert.Empty(t, req.Spec, "no spec may be built from unresolved values")
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_ValidateConfigDefersUnknowns walks the real
// ValidateConfig path for each way a value can be unknown. Every case also carries a known
// invalid sibling, so deferring one check cannot quietly defer the whole resource.
func TestDeveloperMDMPackageConfigPolicy_ValidateConfigDefersUnknowns(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate         func(*developerMDMPackageConfigPolicyModel)
		siblingSummary string
	}{
		"whole settings map unknown": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = types.MapUnknown(types.StringType)
				m.Clients = stringSet(t, "pip") // known invalid on npm
			},
			siblingSummary: "Clients are PyPI only",
		},
		"settings value unknown": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigSettings(t, map[string]attr.Value{
					"@example:registry": types.StringUnknown(),
					" fetch-retries":    types.StringValue("3"), // known invalid key
				})
			},
			siblingSummary: "Setting key is not in canonical form",
		},
		"whole clients set unknown": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
				m.Clients = types.SetUnknown(types.StringType)
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone) // known invalid on pypi
			},
			siblingSummary: "Registry type \"none\" is npm only",
		},
		"unknown target": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringUnknown()
				m.Clients = stringSet(t, "pip")
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries ": "3"})
			},
			siblingSummary: "Setting key is not in canonical form",
		},
		"unknown selector": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.RegistryType = types.StringUnknown()
				m.Settings = packageConfigStringSettings(t, map[string]string{
					"registry":      "https://registry.example.com/npm/",
					"fetch-retries": " 3",
				})
			},
			siblingSummary: "Setting value is not in canonical form",
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := packageConfigValidateConfig(t, packageConfigModel(tc.mutate))
			assertHasSummary(t, diags, tc.siblingSummary)
			assert.Len(t, diags.Errors(), 1, "only the known invalid sibling should be reported: %v", diags)
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_ValidateConfigCollectionStates keeps the four
// collection states distinct. Null and unknown carry nothing to check; a known map with a
// known value is checked normally; a known map with a null element is an error, not a
// deferral.
func TestDeveloperMDMPackageConfigPolicy_ValidateConfigCollectionStates(t *testing.T) {
	t.Parallel()

	nullElement := packageConfigSettings(t, map[string]attr.Value{"fetch-retries": types.StringNull()})
	unknownElement := packageConfigSettings(t, map[string]attr.Value{"fetch-retries": types.StringUnknown()})

	cases := map[string]struct {
		settings types.Map
		summary  string
	}{
		"null map":                 {settings: types.MapNull(types.StringType)},
		"unknown map":              {settings: types.MapUnknown(types.StringType)},
		"known map":                {settings: packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})},
		"known map, unknown value": {settings: unknownElement},
		"known map, null value":    {settings: nullElement, summary: "Null setting value"},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := packageConfigValidateConfig(t, packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = tc.settings
			}))
			if tc.summary == "" {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
				return
			}
			assertHasSummary(t, diags, tc.summary)
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_ValidateConfigDefaultSurvivesUnknownSettings covers
// the compatibility promise from the other direction: an omitted selector with a wholly
// unknown settings map still resolves to StepSecurity, because the default no longer depends
// on settings. In particular it must not produce a settings-only diagnostic.
func TestDeveloperMDMPackageConfigPolicy_ValidateConfigDefaultSurvivesUnknownSettings(t *testing.T) {
	t.Parallel()

	model := packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.RegistryType = types.StringNull()
		m.Settings = types.MapUnknown(types.StringType)
	})

	assert.False(t, packageConfigValidateConfig(t, model).HasError())
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity,
		developerMDMPackageConfigRegistrySelector(model.RegistryType))
}

func TestDeveloperMDMPackageConfigPolicy_ValidateConfigRejections(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate  func(*developerMDMPackageConfigPolicyModel)
		summary string
	}{
		"settings on pypi": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
				m.Clients = stringSet(t, "pip")
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})
			},
			summary: "Settings are npm only",
		},
		"settings on go": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetGo)
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})
			},
			summary: "Settings are npm only",
		},
		"clients on npm": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Clients = stringSet(t, "pip")
			},
			summary: "Clients are PyPI only",
		},
		"clients on go": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetGo)
				m.Clients = stringSet(t, "pip")
			},
			summary: "Clients are PyPI only",
		},
		"pypi without clients": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
			},
			summary: "Clients are required for PyPI",
		},
		"none on pypi": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
				m.Clients = stringSet(t, "pip")
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
			},
			summary: "Registry type \"none\" is npm only",
		},
		"none on go": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetGo)
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
			},
			summary: "Registry type \"none\" is npm only",
		},
		"none without settings": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
			},
			summary: "Settings-only policy needs a registry setting",
		},
		"none without a registry-bearing setting": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3"})
			},
			summary: "Settings-only policy needs a registry setting",
		},
		"bare registry under the stepsecurity selector": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigStringSettings(t, map[string]string{"registry": "https://registry.example.com/npm/"})
			},
			summary: "Default registry conflicts with the StepSecurity registry",
		},
		"null client element": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Target = types.StringValue(stepsecurityapi.DeveloperMDMTargetPyPI)
				set, diags := types.SetValue(types.StringType, []attr.Value{types.StringNull()})
				require.False(t, diags.HasError(), "%v", diags)
				m.Clients = set
			},
			summary: "Null client",
		},
		"untrimmed setting key": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigStringSettings(t, map[string]string{"\tfetch-retries": "3"})
			},
			summary: "Setting key is not in canonical form",
		},
		"untrimmed setting value": {
			mutate: func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigStringSettings(t, map[string]string{"fetch-retries": "3 "})
			},
			summary: "Setting value is not in canonical form",
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := packageConfigValidateConfig(t, packageConfigModel(tc.mutate))
			assertHasSummary(t, diags, tc.summary)
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_ValidateConfigRegistryURLs is the load-bearing
// canonicalization group: the API rewrites a non-canonical registry URL, so accepting one
// here surfaces later as "Provider produced inconsistent result after apply" instead of a
// diagnostic the user can act on.
func TestDeveloperMDMPackageConfigPolicy_ValidateConfigRegistryURLs(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		url     string
		summary string
	}{
		"canonical":              {url: "https://registry.example.com/npm/"},
		"canonical with port":    {url: "https://registry.example.com:8443/npm/"},
		"canonical root path":    {url: "https://registry.example.com/"},
		"plain http":             {url: "http://registry.example.com/npm/", summary: "Registry URL must use https"},
		"embedded credentials":   {url: "https://user:secret@registry.example.com/npm/", summary: "Registry URL must not embed credentials"},
		"query string":           {url: "https://registry.example.com/npm/?token=x", summary: "Registry URL must not contain a query or fragment"},
		"bare question mark":     {url: "https://registry.example.com/npm/?", summary: "Registry URL must not contain a query or fragment"},
		"fragment":               {url: "https://registry.example.com/npm/#frag", summary: "Registry URL must not contain a query or fragment"},
		"uppercase host":         {url: "https://Registry.Example.com/npm/", summary: "Registry URL is not in canonical form"},
		"missing trailing slash": {url: "https://registry.example.com/npm", summary: "Registry URL is not in canonical form"},
		"doubled trailing slash": {url: "https://registry.example.com/npm//", summary: "Registry URL is not in canonical form"},
		"no host":                {url: "https:///npm/", summary: "Registry URL must include a host"},
		// The API canonicalizes the escaped path, so the escaped form is what must round-trip.
		"percent-encoded space": {url: "https://registry.example.com/my%20feed/"},
		"encoded slash in path": {url: "https://registry.example.com/a%2Fb/"},
		"unescaped space":       {url: "https://registry.example.com/my feed/", summary: "Registry URL is not in canonical form"},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Scoped so the bare-registry conflict check does not fire on the valid rows.
			diags := packageConfigValidateConfig(t, packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
				m.Settings = packageConfigStringSettings(t, map[string]string{"@example:registry": tc.url})
			}))
			if tc.summary == "" {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
				return
			}
			assertHasSummary(t, diags, tc.summary)
		})
	}
}

// TestDeveloperMDMPackageConfigPolicy_ValidateConfigDoesNotEchoSettingValues keeps a
// credential reference out of the diagnostics: the offending key is enough to locate it.
func TestDeveloperMDMPackageConfigPolicy_ValidateConfigDoesNotEchoSettingValues(t *testing.T) {
	t.Parallel()

	const secret = "s3cret-token-value"
	diags := packageConfigValidateConfig(t, packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.Settings = packageConfigStringSettings(t, map[string]string{
			"//registry.example.com/npm/:_authToken": secret + " ",
		})
	}))
	require.True(t, diags.HasError())
	for _, d := range diags.Errors() {
		assert.NotContains(t, d.Detail(), secret)
		assert.NotContains(t, d.Summary(), secret)
	}
}

// TestDeveloperMDMPackageConfigPolicy_CollectionSizeValidators covers the schema-level
// validators, which run before ValidateConfig: an explicitly empty collection is an error,
// while removal is expressed by omitting the attribute.
func TestDeveloperMDMPackageConfigPolicy_CollectionSizeValidators(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	attrs := packageConfigSchema(t).Attributes

	settings, ok := attrs["settings"].(schema.MapAttribute)
	require.True(t, ok)
	emptyMap, mapDiags := types.MapValue(types.StringType, map[string]attr.Value{})
	require.False(t, mapDiags.HasError(), "%v", mapDiags)
	var settingsDiags diag.Diagnostics
	for _, v := range settings.Validators {
		resp := &validator.MapResponse{}
		v.ValidateMap(ctx, validator.MapRequest{Path: path.Root("settings"), ConfigValue: emptyMap}, resp)
		settingsDiags.Append(resp.Diagnostics...)
	}
	assert.True(t, settingsDiags.HasError(), "an explicitly empty settings map must be rejected")

	// The backend caps keys and values in bytes, so a multi-byte key under the rune count but
	// over the byte cap has to fail here rather than at the API.
	oversizedKey := strings.Repeat("é", developerMDMMaxNPMSettingKeyBytes/2+1)
	require.Less(t, utf8.RuneCountInString(oversizedKey), developerMDMMaxNPMSettingKeyBytes)
	require.Greater(t, len(oversizedKey), developerMDMMaxNPMSettingKeyBytes)
	oversized := packageConfigStringSettings(t, map[string]string{oversizedKey: "x"})
	var oversizedDiags diag.Diagnostics
	for _, v := range settings.Validators {
		resp := &validator.MapResponse{}
		v.ValidateMap(ctx, validator.MapRequest{Path: path.Root("settings"), ConfigValue: oversized}, resp)
		oversizedDiags.Append(resp.Diagnostics...)
	}
	assert.True(t, oversizedDiags.HasError(), "a setting key over %d bytes must be rejected", developerMDMMaxNPMSettingKeyBytes)

	clients, ok := attrs["clients"].(schema.SetAttribute)
	require.True(t, ok)
	emptySet, setDiags := types.SetValue(types.StringType, []attr.Value{})
	require.False(t, setDiags.HasError(), "%v", setDiags)
	badSet := stringSet(t, "poetry")
	for name, value := range map[string]types.Set{"empty": emptySet, "unsupported member": badSet} {
		var clientDiags diag.Diagnostics
		for _, v := range clients.Validators {
			resp := &validator.SetResponse{}
			v.ValidateSet(ctx, validator.SetRequest{Path: path.Root("clients"), ConfigValue: value}, resp)
			clientDiags.Append(resp.Diagnostics...)
		}
		assert.True(t, clientDiags.HasError(), "%s clients must be rejected", name)
	}
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
	applyDeveloperMDMPackageConfigPolicyToModel(context.Background(), policy, &model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, "pol-123", model.ID.ValueString())
	assert.Equal(t, "pol-123", model.PolicyID.ValueString())
	assert.Equal(t, "npm secure registry", model.Name.ValueString())
	assert.Equal(t, "desc", model.Description.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, model.Target.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, model.RegistryType.ValueString())
	assert.Equal(t, "alice", model.CreatedBy.ValueString())
	assert.Equal(t, "bob", model.UpdatedBy.ValueString())
	assert.True(t, model.Settings.IsNull(), "absent settings must reset to a typed null")
	assert.True(t, model.Clients.IsNull(), "absent clients must reset to a typed null")
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
	applyDeveloperMDMPackageConfigPolicyToModel(context.Background(), policy, &model, &diags)
	require.False(t, diags.HasError(), "unexpected diags: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetNPM, model.Target.ValueString())
	assert.Equal(t, stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity, model.RegistryType.ValueString())
	assert.True(t, model.Description.IsNull(), "empty description should map to null")
}

// TestDeveloperMDMPackageConfigPolicy_ApplyToModelShapes covers the read and import mapping
// for every shape. A settings-only response maps to "none": the resource must never invent a
// StepSecurity registry the policy does not have.
func TestDeveloperMDMPackageConfigPolicy_ApplyToModelShapes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		target   string
		spec     string
		selector string
		settings map[string]string
		clients  []string
	}{
		"combined npm": {
			target:   stepsecurityapi.DeveloperMDMTargetNPM,
			spec:     `{"registry":{"type":"stepsecurity"},"settings":{"fetch-retries":"3"}}`,
			selector: stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity,
			settings: map[string]string{"fetch-retries": "3"},
		},
		"settings only npm": {
			target:   stepsecurityapi.DeveloperMDMTargetNPM,
			spec:     `{"settings":{"registry":"https://registry.example.com/npm/"}}`,
			selector: stepsecurityapi.DeveloperMDMRegistryTypeNone,
			settings: map[string]string{"registry": "https://registry.example.com/npm/"},
		},
		"pypi": {
			target:   stepsecurityapi.DeveloperMDMTargetPyPI,
			spec:     `{"registry":{"type":"stepsecurity"},"clients":["pip","uv"]}`,
			selector: stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity,
			clients:  []string{"pip", "uv"},
		},
		"go": {
			target:   stepsecurityapi.DeveloperMDMTargetGo,
			spec:     `{"registry":{"type":"stepsecurity"}}`,
			selector: stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			policy := &stepsecurityapi.DeveloperMDMPolicy{
				PolicyID: "pol-1",
				Name:     name,
				Category: stepsecurityapi.DeveloperMDMCategoryPackageConfig,
				Target:   tc.target,
				Spec:     json.RawMessage(tc.spec),
			}

			var model developerMDMPackageConfigPolicyModel
			var diags diag.Diagnostics
			applyDeveloperMDMPackageConfigPolicyToModel(context.Background(), policy, &model, &diags)
			require.False(t, diags.HasError(), "unexpected diags: %v", diags)

			assert.Equal(t, tc.target, model.Target.ValueString())
			assert.Equal(t, tc.selector, model.RegistryType.ValueString())

			if tc.settings == nil {
				assert.True(t, model.Settings.IsNull(), "settings must reset to a typed null")
			} else {
				var settings map[string]string
				require.False(t, model.Settings.ElementsAs(context.Background(), &settings, false).HasError())
				assert.Equal(t, tc.settings, settings)
			}

			if tc.clients == nil {
				assert.True(t, model.Clients.IsNull(), "clients must reset to a typed null")
			} else {
				var clients []string
				require.False(t, model.Clients.ElementsAs(context.Background(), &clients, false).HasError())
				assert.ElementsMatch(t, tc.clients, clients)
			}
		})
	}
}

func TestDeveloperMDMPackageConfigPolicy_ApplyToModelRejectsWrongCategory(t *testing.T) {
	t.Parallel()

	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "pol-789",
		Category: stepsecurityapi.DeveloperMDMCategoryIDEExtension,
	}

	var model developerMDMPackageConfigPolicyModel
	var diags diag.Diagnostics
	applyDeveloperMDMPackageConfigPolicyToModel(context.Background(), policy, &model, &diags)
	assert.True(t, diags.HasError(), "expected an error for a non-package_config category")
}

func TestDeveloperMDMPackageConfigPolicy_ApplyToModelRejectsUnsupportedTarget(t *testing.T) {
	t.Parallel()

	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "pol-790",
		Category: stepsecurityapi.DeveloperMDMCategoryPackageConfig,
		Target:   "cargo",
		Spec:     json.RawMessage(`{"registry":{"type":"stepsecurity"}}`),
	}

	var model developerMDMPackageConfigPolicyModel
	var diags diag.Diagnostics
	applyDeveloperMDMPackageConfigPolicyToModel(context.Background(), policy, &model, &diags)
	assert.True(t, diags.HasError(), "expected an error for a target the resource cannot represent")
}

// TestDeveloperMDMPackageConfigPolicy_SecureRegistryHint keeps the 409 explanation attached
// only to policies that actually ask for the secure registry. A settings-only npm policy
// never reaches that gate, so claiming otherwise sends the user after the wrong problem.
func TestDeveloperMDMPackageConfigPolicy_SecureRegistryHint(t *testing.T) {
	t.Parallel()

	withStepSecurity := packageConfigModel()
	assert.Contains(t, developerMDMPackageConfigSecureRegistryHint(withStepSecurity), "409")

	omittedSelector := packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.RegistryType = types.StringNull()
	})
	assert.Contains(t, developerMDMPackageConfigSecureRegistryHint(omittedSelector), "409")

	settingsOnly := packageConfigModel(func(m *developerMDMPackageConfigPolicyModel) {
		m.RegistryType = types.StringValue(stepsecurityapi.DeveloperMDMRegistryTypeNone)
	})
	assert.Empty(t, developerMDMPackageConfigSecureRegistryHint(settingsOnly))
}

// TestAccDeveloperMDMPackageConfigPolicyResource runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
//
// The npm settings come from a terraform_data output rather than a literal, so the first
// plan carries a known map with an unknown value -- the state a configuration reaches when
// it sources a registry URL from another resource. It must plan without inventing a value,
// apply the resolved spec, and then produce a no-change plan. terraform_data.output is
// deliberate: Terraform refines a resource id as known-non-null, so sourcing from .id would
// collapse at plan time and exercise nothing.
func TestAccDeveloperMDMPackageConfigPolicyResource(t *testing.T) {
	const resourceName = "stepsecurity_developer_mdm_package_config_policy.test"
	const name = "tf-acc package config policy"

	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create: combined npm with an omitted selector, sourced from a computed output.
			{
				Config: testAccDeveloperMDMPackageConfigPolicyComputedConfig(name, "combined npm"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(resourceName, "name", name),
					resourcehelper.TestCheckResourceAttr(resourceName, "target", stepsecurityapi.DeveloperMDMTargetNPM),
					resourcehelper.TestCheckResourceAttr(resourceName, "registry_type", stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity),
					resourcehelper.TestCheckResourceAttr(resourceName, "settings.%", "2"),
					resourcehelper.TestCheckResourceAttr(resourceName, "settings.fetch-retries", "3"),
					resourcehelper.TestCheckResourceAttrSet(resourceName, "policy_id"),
					resourcehelper.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Import by policy_id.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update: drop to a settings-only policy, which needs the explicit selector. The
			// selector comes from a computed output, so a value that was known in state goes
			// unknown at plan time and must not be filled in from the prior state.
			{
				Config: testAccDeveloperMDMPackageConfigPolicySettingsOnlyConfig(name, "settings only"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(resourceName, "registry_type", stepsecurityapi.DeveloperMDMRegistryTypeNone),
					resourcehelper.TestCheckResourceAttr(resourceName, "settings.%", "1"),
					resourcehelper.TestCheckNoResourceAttr(resourceName, "clients.#"),
				),
			},
			// The same shape written literally is not a change.
			{
				Config:   testAccDeveloperMDMPackageConfigPolicyLiteralSettingsOnlyConfig(name, "settings only"),
				PlanOnly: true,
			},
		},
	})
}

// TestAccDeveloperMDMPackageConfigPolicyPyPIResource exercises the PyPI shape, including a
// client-set change in place: only a target change may force replacement.
func TestAccDeveloperMDMPackageConfigPolicyPyPIResource(t *testing.T) {
	const resourceName = "stepsecurity_developer_mdm_package_config_policy.pypi"
	const name = "tf-acc pypi package config policy"

	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccDeveloperMDMPackageConfigPolicyPyPIConfig(name, `["pip", "uv"]`),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(resourceName, "target", stepsecurityapi.DeveloperMDMTargetPyPI),
					resourcehelper.TestCheckResourceAttr(resourceName, "registry_type", stepsecurityapi.DeveloperMDMRegistryTypeStepSecurity),
					resourcehelper.TestCheckResourceAttr(resourceName, "clients.#", "2"),
					resourcehelper.TestCheckNoResourceAttr(resourceName, "settings.%"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Reordering a set is not a change.
			{
				Config:   testAccDeveloperMDMPackageConfigPolicyPyPIConfig(name, `["uv", "pip"]`),
				PlanOnly: true,
			},
			{
				Config: testAccDeveloperMDMPackageConfigPolicyPyPIConfig(name, `["pip"]`),
				Check:  resourcehelper.TestCheckResourceAttr(resourceName, "clients.#", "1"),
			},
		},
	})
}

func testAccDeveloperMDMPackageConfigPolicyComputedConfig(name, description string) string {
	return fmt.Sprintf(`
resource "terraform_data" "registry" {
  input = "https://registry.example.com/npm/"
}

resource "stepsecurity_developer_mdm_package_config_policy" "test" {
  name        = %q
  description = %q

  settings = {
    "@example:registry" = terraform_data.registry.output
    "fetch-retries"     = "3"
  }
}
`, name, description)
}

func testAccDeveloperMDMPackageConfigPolicySettingsOnlyConfig(name, description string) string {
	return fmt.Sprintf(`
resource "terraform_data" "selector" {
  input = "none"
}

resource "stepsecurity_developer_mdm_package_config_policy" "test" {
  name          = %q
  description   = %q
  registry_type = terraform_data.selector.output

  settings = {
    "@example:registry" = "https://registry.example.com/npm/"
  }
}
`, name, description)
}

func testAccDeveloperMDMPackageConfigPolicyLiteralSettingsOnlyConfig(name, description string) string {
	return fmt.Sprintf(`
resource "terraform_data" "selector" {
  input = "none"
}

resource "stepsecurity_developer_mdm_package_config_policy" "test" {
  name          = %q
  description   = %q
  registry_type = "none"

  settings = {
    "@example:registry" = "https://registry.example.com/npm/"
  }
}
`, name, description)
}

func testAccDeveloperMDMPackageConfigPolicyPyPIConfig(name, clients string) string {
	return fmt.Sprintf(`
resource "stepsecurity_developer_mdm_package_config_policy" "pypi" {
  name    = %q
  target  = "pypi"
  clients = %s
}
`, name, clients)
}
