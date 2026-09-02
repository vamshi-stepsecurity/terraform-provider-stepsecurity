package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &developerMDMIDEExtensionPolicyResource{}
	_ resource.ResourceWithConfigure      = &developerMDMIDEExtensionPolicyResource{}
	_ resource.ResourceWithValidateConfig = &developerMDMIDEExtensionPolicyResource{}
	_ resource.ResourceWithImportState    = &developerMDMIDEExtensionPolicyResource{}
)

// Identifier and version shapes mirrored from backend validation.
const (
	developerMDMIdentifierPattern = `^[A-Za-z0-9][A-Za-z0-9-]*$`
	developerMDMVersionPattern    = `^\d+\.\d+\.\d+(@[A-Za-z0-9._-]+)?$`
)

var (
	developerMDMIdentifierRegex = regexp.MustCompile(developerMDMIdentifierPattern)
	developerMDMVersionRegex    = regexp.MustCompile(developerMDMVersionPattern)
)

// NewDeveloperMDMIDEExtensionPolicyResource is a helper function to simplify the provider implementation.
func NewDeveloperMDMIDEExtensionPolicyResource() resource.Resource {
	return &developerMDMIDEExtensionPolicyResource{}
}

// developerMDMIDEExtensionPolicyResource is the resource implementation.
type developerMDMIDEExtensionPolicyResource struct {
	client stepsecurityapi.Client
}

// developerMDMIDEExtensionPolicyModel maps the resource schema data.
type developerMDMIDEExtensionPolicyModel struct {
	ID          types.String `tfsdk:"id"`
	PolicyID    types.String `tfsdk:"policy_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Target      types.String `tfsdk:"target"`
	Mode        types.String `tfsdk:"mode"`
	// Rules is a framework list rather than a Go slice so the whole list can be unknown.
	// A slice cannot represent that state, and a config sourcing rules from an unresolved
	// expression (a local, a module output, another resource's computed attribute) arrives
	// with the entire list unknown on the first plan.
	Rules             types.List   `tfsdk:"rules"`
	GalleryServiceURL types.String `tfsdk:"gallery_service_url"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedBy         types.String `tfsdk:"updated_by"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

// developerMDMIDEExtensionRuleModel maps a single allow/block rule. It is the decoded
// representation of one known element of the rules list; its framework value types still
// carry attribute-level unknowns.
type developerMDMIDEExtensionRuleModel struct {
	Publisher types.String `tfsdk:"publisher"`
	Name      types.String `tfsdk:"name"`
	Versions  types.Set    `tfsdk:"versions"`
	Stable    types.Bool   `tfsdk:"stable"`
	Comment   types.String `tfsdk:"comment"`
}

// developerMDMIDEExtensionRuleObjectType is the element type of the rules list. It must
// stay in lockstep with the nested schema object above.
func developerMDMIDEExtensionRuleObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"publisher": types.StringType,
			"name":      types.StringType,
			"versions":  types.SetType{ElemType: types.StringType},
			"stable":    types.BoolType,
			"comment":   types.StringType,
		},
	}
}

// decodeDeveloperMDMIDEExtensionRules decodes the rules list into rule models. The bool
// reports whether the list and its elements are structurally known; false means the caller
// must defer anything that needs the rules rather than treat them as an empty list.
// Unknown fields *inside* a known element still decode: those are deferred individually.
func decodeDeveloperMDMIDEExtensionRules(ctx context.Context, value types.List) ([]developerMDMIDEExtensionRuleModel, bool, diag.Diagnostics) {
	// rules is required, so a real config never sends null; schema validation rejects that.
	// Treating it as not-known here just keeps an unsafe conversion from being attempted.
	if value.IsNull() || value.IsUnknown() {
		return nil, false, nil
	}

	// A known list can still hold an entirely unknown object, which has no attributes to
	// decode into the struct. ElementsAs would fail on it, so check before calling it.
	for _, element := range value.Elements() {
		if element.IsUnknown() {
			return nil, false, nil
		}
	}

	var rules []developerMDMIDEExtensionRuleModel
	diags := value.ElementsAs(ctx, &rules, false)
	if diags.HasError() {
		return nil, false, diags
	}
	return rules, true, diags
}

// Metadata returns the resource type name.
func (r *developerMDMIDEExtensionPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_developer_mdm_ide_extension_policy"
}

// Schema defines the schema for the resource.
func (r *developerMDMIDEExtensionPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Developer MDM VS Code extension policy in StepSecurity. " +
			"The policy declares allow/block intent for VS Code extensions; StepSecurity compiles and enforces it on managed devices. " +
			"An empty `allowlist` blocks every extension and an empty `blocklist` allows every extension, so set `rules` deliberately. " +
			"The policy can also point VS Code at a private extension marketplace instead of the public one; see `gallery_service_url`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier. Same value as `policy_id`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"policy_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for this policy generated by StepSecurity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional human-readable description.",
			},
			"target": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(stepsecurityapi.DeveloperMDMTargetVSCode),
				MarkdownDescription: "IDE target for this policy. Defaults to `vscode`.",
				Validators: []validator.String{
					stringvalidator.OneOf(stepsecurityapi.DeveloperMDMTargetVSCode),
				},
			},
			"mode": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Policy mode. `allowlist` permits only the listed extensions and blocks everything else; " +
					"`blocklist` blocks the listed extensions and allows everything else.",
				Validators: []validator.String{
					stringvalidator.OneOf(stepsecurityapi.DeveloperMDMModeAllowlist, stepsecurityapi.DeveloperMDMModeBlocklist),
				},
			},
			"rules": schema.ListNestedAttribute{
				Required: true,
				MarkdownDescription: "Ordered list of allow/block rules. An empty list is valid but powerful: " +
					"empty `allowlist` blocks all extensions, empty `blocklist` allows all extensions.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"publisher": schema.StringAttribute{
							Required: true,
							MarkdownDescription: "VS Code marketplace publisher segment (e.g. `ms-python`). " +
								"No `*`, `.`, or spaces.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"name": schema.StringAttribute{
							Optional: true,
							MarkdownDescription: "VS Code extension name segment (e.g. `python`). " +
								"Omit to target the whole publisher. No `*` or spaces.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"versions": schema.SetAttribute{
							ElementType: types.StringType,
							Optional:    true,
							MarkdownDescription: "Allowlist only. Requires `name`. Exact `major.minor.patch` versions, " +
								"with optional `@platform` suffix. Mutually exclusive with `stable`. " +
								"Do not use the literal `stable`; set `stable = true` instead.",
						},
						"stable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
							MarkdownDescription: "Allowlist only. Allow the extension's stable channel. Mutually exclusive with `versions`.",
						},
						"comment": schema.StringAttribute{
							Optional: true,
							MarkdownDescription: "Optional free-text justification for this rule, recorded for " +
								"compliance review. Descriptive only: it does not affect which extensions " +
								"are allowed or blocked. Omit to leave unset; when set, 1 to 512 characters.",
							Validators: []validator.String{
								stringvalidator.UTF8LengthBetween(1, 512),
							},
						},
					},
				},
			},
			"gallery_service_url": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Optional private VS Code extension marketplace. Sets VS Code's " +
					"`ExtensionGalleryServiceUrl` on managed devices so extension browsing and " +
					"installation resolve against your own gallery instead of the public marketplace. " +
					"Must be an absolute `https` URL with no credentials and no fragment. " +
					"Independent of `mode`: valid on both an allowlist and a blocklist. " +
					"Omit to leave the device on the public marketplace.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.LengthAtMost(stepsecurityapi.DeveloperMDMMaxGalleryServiceURLLen),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created this policy.",
			},
			"created_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when this policy was created.",
			},
			"updated_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last updated this policy.",
			},
			"updated_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when this policy was last updated.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *developerMDMIDEExtensionPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// ValidateConfig runs cross-field and cross-rule validation that schema validators cannot express.
func (r *developerMDMIDEExtensionPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model developerMDMIDEExtensionPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateDeveloperMDMIDEExtensionPolicy(ctx, model)...)
}

// Create creates the resource and sets the initial Terraform state.
func (r *developerMDMIDEExtensionPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan developerMDMIDEExtensionPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateDeveloperMDMIDEExtensionPolicy(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiReq := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateDeveloperMDMPolicy(ctx, apiReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating Developer MDM IDE extension policy",
			"Could not create policy, unexpected error: "+err.Error(),
		)
		return
	}

	applyDeveloperMDMPolicyToModel(ctx, created, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *developerMDMIDEExtensionPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state developerMDMIDEExtensionPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetDeveloperMDMPolicy(ctx, state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Developer MDM IDE extension policy",
			"Could not read policy ID "+state.PolicyID.ValueString()+": "+err.Error(),
		)
		return
	}

	applyDeveloperMDMPolicyToModel(ctx, policy, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *developerMDMIDEExtensionPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan developerMDMIDEExtensionPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateDeveloperMDMIDEExtensionPolicy(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiReq := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updated, err := r.client.UpdateDeveloperMDMPolicy(ctx, plan.PolicyID.ValueString(), apiReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating Developer MDM IDE extension policy",
			"Could not update policy, unexpected error: "+err.Error(),
		)
		return
	}

	applyDeveloperMDMPolicyToModel(ctx, updated, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *developerMDMIDEExtensionPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state developerMDMIDEExtensionPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteDeveloperMDMPolicy(ctx, state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting Developer MDM IDE extension policy",
			"Could not delete policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState imports the resource by backend policy_id and lets Read populate the rest.
func (r *developerMDMIDEExtensionPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("policy_id"), req, resp)
}

// validateDeveloperMDMIDEExtensionPolicy enforces field, cross-field, and cross-rule rules
// that mirror the backend. It is called from ValidateConfig and from create/update builders.
func validateDeveloperMDMIDEExtensionPolicy(ctx context.Context, model developerMDMIDEExtensionPolicyModel) diag.Diagnostics {
	var diags diag.Diagnostics

	if !model.GalleryServiceURL.IsNull() && !model.GalleryServiceURL.IsUnknown() {
		if summary, detail := validateGalleryServiceURL(model.GalleryServiceURL.ValueString()); summary != "" {
			diags.AddAttributeError(path.Root("gallery_service_url"), summary, detail)
		}
	}

	// Rule-level and cross-rule checks need the rules themselves. When the list is not yet
	// known there is nothing to check: defer rather than read it as an empty list, which
	// would invent duplicate-rule and missing-name diagnostics from values Terraform has
	// not resolved. Create and update re-validate once it is known.
	rules, rulesKnown, ruleDiags := decodeDeveloperMDMIDEExtensionRules(ctx, model.Rules)
	diags.Append(ruleDiags...)
	if diags.HasError() || !rulesKnown {
		return diags
	}

	isBlocklist := model.Mode.ValueString() == stepsecurityapi.DeveloperMDMModeBlocklist

	// Track compiled key (publisher + name) to reject mixing stable and explicit versions.
	type keyState struct{ stable, versions bool }
	states := map[string]*keyState{}

	for idx, rule := range rules {
		rulePath := path.Root("rules").AtListIndex(idx)

		publisher := rule.Publisher.ValueString()
		if !rule.Publisher.IsUnknown() && !developerMDMIdentifierRegex.MatchString(publisher) {
			diags.AddAttributeError(
				rulePath.AtName("publisher"),
				"Invalid publisher",
				fmt.Sprintf("Publisher %q must match %s (no '*', '.', or spaces).", publisher, developerMDMIdentifierPattern),
			)
		}

		hasName := !rule.Name.IsNull() && !rule.Name.IsUnknown() && rule.Name.ValueString() != ""
		name := rule.Name.ValueString()
		if hasName && !developerMDMIdentifierRegex.MatchString(name) {
			diags.AddAttributeError(
				rulePath.AtName("name"),
				"Invalid extension name",
				fmt.Sprintf("Name %q must match %s (no '*' or spaces).", name, developerMDMIdentifierPattern),
			)
		}

		var versions []string
		if !rule.Versions.IsNull() && !rule.Versions.IsUnknown() {
			diags.Append(rule.Versions.ElementsAs(ctx, &versions, false)...)
		}
		hasVersions := len(versions) > 0
		stable := rule.Stable.ValueBool()

		if isBlocklist {
			if hasVersions {
				diags.AddAttributeError(
					rulePath.AtName("versions"),
					"Versions not allowed on a blocklist",
					"`versions` is allowlist-only. Remove versions from blocklist rules.",
				)
			}
			if stable {
				diags.AddAttributeError(
					rulePath.AtName("stable"),
					"stable not allowed on a blocklist",
					"`stable` is allowlist-only. Remove `stable = true` from blocklist rules.",
				)
			}
		} else {
			// Defer when name is unknown (e.g. computed from an expression): it may
			// resolve to a valid value at apply time, and create/update re-validates
			// once it is known. Only reject when name is explicitly absent.
			if hasVersions && !hasName && !rule.Name.IsUnknown() {
				diags.AddAttributeError(
					rulePath.AtName("versions"),
					"versions require name",
					"`versions` can only be set on a rule that also sets `name`.",
				)
			}
			if stable && hasVersions {
				diags.AddAttributeError(
					rulePath.AtName("stable"),
					"stable and versions are mutually exclusive",
					"A rule may set `stable = true` or `versions`, not both.",
				)
			}
			for _, v := range versions {
				if v == "stable" {
					diags.AddAttributeError(
						rulePath.AtName("versions"),
						"Literal version \"stable\" is not allowed",
						"Set `stable = true` instead of listing the literal version \"stable\".",
					)
					continue
				}
				if !developerMDMVersionRegex.MatchString(v) {
					diags.AddAttributeError(
						rulePath.AtName("versions"),
						"Invalid version",
						fmt.Sprintf("Version %q must be major.minor.patch with an optional @platform suffix.", v),
					)
				}
			}
		}

		// Cross-rule conflict tracking compares the compiled key (publisher + name).
		// Skip when either segment is unknown: the real key is not known yet, so a
		// zero-value ValueString() would falsely collide distinct extensions (e.g. an
		// unknown-name versions rule with a whole-publisher stable rule). Create/update
		// re-validates once the values are known.
		if !rule.Publisher.IsUnknown() && !rule.Name.IsUnknown() {
			key := publisher + "\x00" + name
			st := states[key]
			if st == nil {
				st = &keyState{}
				states[key] = st
			}
			if stable {
				st.stable = true
			}
			if hasVersions {
				st.versions = true
			}
			if st.stable && st.versions {
				display := publisher
				if name != "" {
					display += "." + name
				}
				diags.AddError(
					"Conflicting rules for the same extension",
					fmt.Sprintf("Extension %q cannot mix `stable` and explicit `versions` across rules.", display),
				)
			}
		}
	}

	return diags
}

// validateGalleryServiceURL mirrors the backend's URL rules so a bad value fails at plan
// time instead of as an opaque 400. An empty summary means the value is acceptable.
func validateGalleryServiceURL(raw string) (summary, detail string) {
	if len(raw) > stepsecurityapi.DeveloperMDMMaxGalleryServiceURLLen {
		return "Marketplace URL too long", fmt.Sprintf(
			"`gallery_service_url` must be at most %d characters.",
			stepsecurityapi.DeveloperMDMMaxGalleryServiceURLLen)
	}
	if raw != strings.TrimSpace(raw) {
		return "Marketplace URL has surrounding whitespace",
			"`gallery_service_url` must not have leading or trailing whitespace."
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "Marketplace URL contains control characters",
				"`gallery_service_url` must not contain control characters."
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "Invalid marketplace URL",
			fmt.Sprintf("`gallery_service_url` is not a valid URL: %s", err.Error())
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "Marketplace URL must use https",
			"`gallery_service_url` must use the `https` scheme."
	}
	if u.Host == "" {
		return "Marketplace URL has no host",
			"`gallery_service_url` must include a host."
	}
	if u.User != nil {
		return "Marketplace URL contains credentials",
			"`gallery_service_url` must not contain userinfo (credentials). " +
				"Configure gallery authentication on the device, not in the policy."
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "Marketplace URL contains a fragment",
			"`gallery_service_url` must not contain a `#` fragment."
	}
	return "", ""
}

// buildDeveloperMDMIDEExtensionPolicyRequest converts the model into an API request body.
func buildDeveloperMDMIDEExtensionPolicyRequest(ctx context.Context, model developerMDMIDEExtensionPolicyModel, diags *diag.Diagnostics) stepsecurityapi.DeveloperMDMPolicyRequest {
	ruleModels, rulesKnown, ruleDiags := decodeDeveloperMDMIDEExtensionRules(ctx, model.Rules)
	diags.Append(ruleDiags...)
	if diags.HasError() {
		return stepsecurityapi.DeveloperMDMPolicyRequest{}
	}
	// Terraform resolves a required attribute before create or update, so this is a guard
	// rather than a reachable path today. It exists so a future lifecycle change surfaces as
	// an explicit error instead of silently shipping an empty rule list to the backend --
	// which on an allowlist would block every extension.
	if !rulesKnown {
		diags.AddAttributeError(
			path.Root("rules"),
			"Rules are not fully known",
			"`rules` must be fully known before the IDE extension policy can be created or updated.",
		)
		return stepsecurityapi.DeveloperMDMPolicyRequest{}
	}

	rules := make([]stepsecurityapi.DeveloperMDMIDEExtensionRule, 0, len(ruleModels))
	for _, r := range ruleModels {
		rule := stepsecurityapi.DeveloperMDMIDEExtensionRule{
			Publisher: r.Publisher.ValueString(),
			Name:      r.Name.ValueString(),
			Versions:  sortedStringSet(ctx, r.Versions, diags),
			Stable:    r.Stable.ValueBool(),
			Comment:   r.Comment.ValueString(),
		}
		rules = append(rules, rule)
	}

	spec := stepsecurityapi.DeveloperMDMIDEExtensionSpec{
		Rules:             rules,
		GalleryServiceURL: model.GalleryServiceURL.ValueString(),
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		diags.AddError("Failed to encode policy spec", err.Error())
	}

	return stepsecurityapi.DeveloperMDMPolicyRequest{
		Name:        model.Name.ValueString(),
		Description: model.Description.ValueString(),
		Category:    stepsecurityapi.DeveloperMDMCategoryIDEExtension,
		Target:      developerMDMPolicyTarget(model.Target),
		SpecVersion: stepsecurityapi.DeveloperMDMSpecVersionIDEExtension,
		Mode:        model.Mode.ValueString(),
		Spec:        specJSON,
	}
}

func developerMDMPolicyTarget(target types.String) string {
	if target.IsNull() || target.IsUnknown() || target.ValueString() == "" {
		return stepsecurityapi.DeveloperMDMTargetVSCode
	}
	return target.ValueString()
}

// sortedStringSet converts a set into a deterministically sorted slice to avoid spurious diffs.
func sortedStringSet(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var values []string
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	sort.Strings(values)
	return values
}

// applyDeveloperMDMPolicyToModel applies an API policy response into the Terraform model.
// It rejects policies whose category is not ide_extension because this resource cannot manage them.
func applyDeveloperMDMPolicyToModel(ctx context.Context, policy *stepsecurityapi.DeveloperMDMPolicy, model *developerMDMIDEExtensionPolicyModel, diags *diag.Diagnostics) {
	if policy.Category != stepsecurityapi.DeveloperMDMCategoryIDEExtension {
		diags.AddError(
			"Unsupported Developer MDM policy category",
			fmt.Sprintf(
				"Policy %q has category %q, but stepsecurity_developer_mdm_ide_extension_policy only manages %q policies.",
				policy.PolicyID, policy.Category, stepsecurityapi.DeveloperMDMCategoryIDEExtension,
			),
		)
		return
	}

	model.ID = types.StringValue(policy.PolicyID)
	model.PolicyID = types.StringValue(policy.PolicyID)
	model.Name = types.StringValue(policy.Name)
	target := policy.Target
	if target == "" {
		target = stepsecurityapi.DeveloperMDMTargetVSCode
	}
	model.Target = types.StringValue(target)
	model.Mode = types.StringValue(policy.Mode)
	model.CreatedBy = types.StringValue(policy.CreatedBy)
	model.CreatedAt = types.StringValue(policy.CreatedAt)
	model.UpdatedBy = types.StringValue(policy.UpdatedBy)
	model.UpdatedAt = types.StringValue(policy.UpdatedAt)

	if policy.Description != "" {
		model.Description = types.StringValue(policy.Description)
	} else {
		model.Description = types.StringNull()
	}

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	if len(policy.Spec) > 0 {
		if err := json.Unmarshal(policy.Spec, &spec); err != nil {
			diags.AddError("Failed to decode policy spec", err.Error())
			return
		}
	}

	if spec.GalleryServiceURL != "" {
		model.GalleryServiceURL = types.StringValue(spec.GalleryServiceURL)
	} else {
		model.GalleryServiceURL = types.StringNull()
	}

	rules := make([]developerMDMIDEExtensionRuleModel, 0, len(spec.Rules))
	for _, r := range spec.Rules {
		rule := developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue(r.Publisher),
			Stable:    types.BoolValue(r.Stable),
		}
		if r.Name != "" {
			rule.Name = types.StringValue(r.Name)
		} else {
			rule.Name = types.StringNull()
		}
		if len(r.Versions) > 0 {
			versionValues := make([]attr.Value, len(r.Versions))
			for i, v := range r.Versions {
				versionValues[i] = types.StringValue(v)
			}
			setValue, setDiags := types.SetValue(types.StringType, versionValues)
			diags.Append(setDiags...)
			rule.Versions = setValue
		} else {
			rule.Versions = types.SetNull(types.StringType)
		}
		if r.Comment != "" {
			rule.Comment = types.StringValue(r.Comment)
		} else {
			rule.Comment = types.StringNull()
		}
		rules = append(rules, rule)
	}

	// A policy with no rules must read back as a known empty list, never null: an empty
	// allowlist blocks every extension and an empty blocklist allows every extension, so the
	// distinction is meaningful. `rules` is non-nil above, which is what keeps it known.
	rulesValue, rulesDiags := types.ListValueFrom(ctx, developerMDMIDEExtensionRuleObjectType(), rules)
	diags.Append(rulesDiags...)
	if diags.HasError() {
		return
	}
	model.Rules = rulesValue
}
