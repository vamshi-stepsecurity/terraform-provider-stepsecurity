package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

var (
	_ resource.Resource                   = &secureRegistryPolicyResource{}
	_ resource.ResourceWithConfigure      = &secureRegistryPolicyResource{}
	_ resource.ResourceWithImportState    = &secureRegistryPolicyResource{}
	_ resource.ResourceWithValidateConfig = &secureRegistryPolicyResource{}
)

// cooldownControlAttrTypes defines the types for the cooldown_control nested object.
var cooldownControlAttrTypes = map[string]attr.Type{
	"enabled":        types.BoolType,
	"period_in_days": types.Int64Type,
	"exemption_list": types.SetType{ElemType: types.StringType},
}

// compromisedPackagesControlAttrTypes defines the types for the compromised_packages_control nested object.
var compromisedPackagesControlAttrTypes = map[string]attr.Type{
	"enabled": types.BoolType,
}

// typosquattingControlAttrTypes defines the types for the typosquatting_control nested object.
var typosquattingControlAttrTypes = map[string]attr.Type{
	"enabled":        types.BoolType,
	"exemption_list": types.SetType{ElemType: types.StringType},
}

// customBlockListControlAttrTypes defines the types for the custom_block_list_control nested object.
var customBlockListControlAttrTypes = map[string]attr.Type{
	"enabled":               types.BoolType,
	"patterns":              types.SetType{ElemType: types.StringType},
	"block_pseudo_versions": types.SetType{ElemType: types.StringType},
	"block_yanked_versions": types.BoolType,
}

// goSettingsAttrTypes defines the types for the go_settings nested object.
var goSettingsAttrTypes = map[string]attr.Type{
	"proxy_checksum_db": types.BoolType,
}

// npmSettingsAttrTypes defines the types for the npm_settings nested object.
var npmSettingsAttrTypes = map[string]attr.Type{
	"rewrite_tarball_urls":            types.BoolType,
	"block_message_template":          types.StringType,
	"hidden_versions_notice_template": types.StringType,
}

func NewSecureRegistryPolicyResource() resource.Resource {
	return &secureRegistryPolicyResource{}
}

type secureRegistryPolicyResource struct {
	client stepsecurityapi.Client
}

type secureRegistryPolicyResourceModel struct {
	Registry                   types.String `tfsdk:"registry"`
	CooldownControl            types.Object `tfsdk:"cooldown_control"`
	CompromisedPackagesControl types.Object `tfsdk:"compromised_packages_control"`
	TyposquattingControl       types.Object `tfsdk:"typosquatting_control"`
	CustomBlockListControl     types.Object `tfsdk:"custom_block_list_control"`
	NpmSettings                types.Object `tfsdk:"npm_settings"`
	GoSettings                 types.Object `tfsdk:"go_settings"`
}

type cooldownControlModel struct {
	Enabled       types.Bool  `tfsdk:"enabled"`
	PeriodInDays  types.Int64 `tfsdk:"period_in_days"`
	ExemptionList types.Set   `tfsdk:"exemption_list"`
}

type compromisedPackagesControlModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type typosquattingControlModel struct {
	Enabled       types.Bool `tfsdk:"enabled"`
	ExemptionList types.Set  `tfsdk:"exemption_list"`
}

type customBlockListControlModel struct {
	Enabled             types.Bool `tfsdk:"enabled"`
	Patterns            types.Set  `tfsdk:"patterns"`
	BlockPseudoVersions types.Set  `tfsdk:"block_pseudo_versions"`
	BlockYankedVersions types.Bool `tfsdk:"block_yanked_versions"`
}

type goSettingsModel struct {
	ProxyChecksumDB types.Bool `tfsdk:"proxy_checksum_db"`
}

type npmSettingsModel struct {
	RewriteTarballURLs           types.Bool   `tfsdk:"rewrite_tarball_urls"`
	BlockMessageTemplate         types.String `tfsdk:"block_message_template"`
	HiddenVersionsNoticeTemplate types.String `tfsdk:"hidden_versions_notice_template"`
}

func (r *secureRegistryPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secure_registry_policy"
}

func (r *secureRegistryPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Secure Registry policy for a package registry in StepSecurity. Controls which packages are allowed or blocked based on configurable security rules.",
		Attributes: map[string]schema.Attribute{
			"registry": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The package registry to configure. Currently supported: `npm`, `pypi`, `maven`, `nuget`, `go`, `ruby`, `cargo`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("npm", "pypi", "maven", "nuget", "go", "ruby", "cargo"),
				},
			},
			"cooldown_control": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Blocks packages published within a configurable number of days, giving the community time to vet new releases.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the cooldown control is enabled.",
					},
					"period_in_days": schema.Int64Attribute{
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(1),
						MarkdownDescription: "Number of days to quarantine newly-published package versions. Must be between 1 and 30.",
						Validators: []validator.Int64{
							int64validator.Between(1, 30),
						},
					},
					"exemption_list": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Packages exempt from the cooldown period. Supports exact names, version globs (`package@*`), and exact versions (`package@1.2.3`). For npm, scoped wildcards (`@scope/*`) are also supported. Order-insensitive — reordering entries produces no plan diff.",
					},
				},
			},
			"compromised_packages_control": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Blocks packages flagged as compromised or reported as malicious by the security community.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the compromised packages control is enabled.",
					},
				},
			},
			"typosquatting_control": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Blocks packages whose names are heuristically similar to popular packages (advisory typosquatting detection). Only applicable when `registry = \"npm\"`; setting this for any other registry raises a plan-time error.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the typosquatting control is enabled.",
					},
					"exemption_list": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Package names exempt from typosquatting detection, overriding false positives. Order-insensitive — reordering entries produces no plan diff.",
					},
				},
			},
			"custom_block_list_control": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Explicitly blocks packages or versions matching configured glob patterns. Supported for `npm`, `pypi`, `nuget`, `go`, `ruby` and `cargo`; not applicable to `maven`.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the custom block list control is enabled.",
					},
					"patterns": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Package/version glob patterns to block. Supports exact names, version globs (`package@*`), and exact versions (`package@1.2.3`). For npm, scoped wildcards (`@scope/*`) are also supported. Order-insensitive — reordering entries produces no plan diff.",
					},
					"block_pseudo_versions": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Module globs whose versions must be released tags. Pseudo-versions and raw commit or branch revisions are refused for matching modules; `*` applies the rule to every module. Only applicable when `registry = \"go\"`; setting this for any other registry raises a plan-time error. Order-insensitive.",
					},
					"block_yanked_versions": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Hard-blocks crate versions that crates.io has yanked, even when they are pinned in a `Cargo.lock`. Only applicable when `registry = \"cargo\"`; setting this for any other registry raises a plan-time error. Defaults to `false`.",
					},
				},
			},
			"go_settings": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Go-specific registry settings. Only applicable when `registry = \"go\"`; setting this for any other registry raises a plan-time error.",
				Attributes: map[string]schema.Attribute{
					"proxy_checksum_db": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Serve the Go checksum database through the secure registry instead of letting the client reach `sum.golang.org` directly. Leave off unless build runners have no egress to `sum.golang.org`; module verification happens either way.",
					},
				},
			},
			"npm_settings": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "npm-specific registry settings. Only applicable when `registry = \"npm\"`; setting this for any other registry raises a plan-time error.",
				Attributes: map[string]schema.Attribute{
					"rewrite_tarball_urls": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether to rewrite `dist.tarball` URLs in npm package metadata so tarballs are served through the secure registry.",
					},
					"block_message_template": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Text appended to the error returned when npm traffic is blocked by Secure Registry (for example, `False positive? Raise a PR against example-org/exclusions for {{package}}.`). It only reaches developers for full-package blocks (typosquatting, compromised package wildcard, block list entries like `name@*`) and tarball downloads. It cannot appear when a single version is silently removed from package metadata (cooldown, compromised version, block list `name@1.2.3`), because that is not an error response. Only npm and yarn classic print the error body; pnpm, yarn berry and bun show only `403 Forbidden`. Supported placeholders: `{{package}}`, `{{version}}` (empty for package-level blocks), `{{control}}` (`typosquatting`, `compromised`, `custom_block_list` or `cooldown`), `{{reason}}` and `{{ecosystem}}`. Maximum 500 characters, a single line of printable text. Removing the attribute clears the message.",
						Validators:          []validator.String{messageTemplate(maxBlockMessageTemplateLen, blockMessagePlaceholders)},
					},
					"hidden_versions_notice_template": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Replaces the default notice shown when cooldown, compromised packages or the custom block list remove versions from a package's metadata. When unset, the default text is used. Only the npm CLI prints it (`npm notice ...`); pnpm, yarn and bun do not. To make npm show it on every install, the registry sends `Cache-Control: no-store` to the npm CLI only, so those package documents are re-downloaded instead of cached. Supported placeholders: `{{package}}`, `{{count}}`, `{{versions}}` (the 2 newest hidden versions), `{{cooldown_days}}` (the configured cooldown period), `{{details}}` (the default per-control text, for example `cooldown (7 days): 26.6.4, 25.9.9 (+2 more)`) and `{{ecosystem}}`. Maximum 300 characters, a single line of printable text. Removing the attribute restores the default text.",
						Validators:          []validator.String{messageTemplate(maxNoticeTemplateLen, noticePlaceholders)},
					},
				},
			},
		},
	}
}

// ValidateConfig rejects controls that the backend does not support for the given
// registry at plan time, giving a clearer error than the backend's 400s.
func (r *secureRegistryPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model secureRegistryPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if model.Registry.IsUnknown() || model.Registry.IsNull() {
		return
	}

	registry := model.Registry.ValueString()

	// Unknown blocks (e.g. derived from a not-yet-computed reference) can't be
	// validated at plan time — defer to the backend's own validation on apply
	// rather than risk a false-positive plan-time error.
	if registry != "npm" && !model.NpmSettings.IsNull() && !model.NpmSettings.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("npm_settings"),
			"npm_settings not applicable",
			fmt.Sprintf("npm_settings is not applicable to registry %q. Remove this block or set registry to \"npm\".", registry),
		)
	}

	if registry != "npm" && !model.TyposquattingControl.IsNull() && !model.TyposquattingControl.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("typosquatting_control"),
			"typosquatting_control not applicable",
			fmt.Sprintf("typosquatting_control is not applicable to registry %q. Remove this block or set registry to \"npm\".", registry),
		)
	}

	if registry != "go" && !model.GoSettings.IsNull() && !model.GoSettings.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("go_settings"),
			"go_settings not applicable",
			fmt.Sprintf("go_settings is not applicable to registry %q. Remove this block or set registry to \"go\".", registry),
		)
	}

	if !model.CustomBlockListControl.IsNull() && !model.CustomBlockListControl.IsUnknown() {
		attrs := model.CustomBlockListControl.Attributes()
		if v, ok := attrs["block_pseudo_versions"].(types.Set); ok && registry != "go" && !v.IsNull() && !v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root("custom_block_list_control").AtName("block_pseudo_versions"),
				"block_pseudo_versions not applicable",
				fmt.Sprintf("block_pseudo_versions is not applicable to registry %q. Remove this attribute or set registry to \"go\".", registry),
			)
		}
		if v, ok := attrs["block_yanked_versions"].(types.Bool); ok && registry != "cargo" && !v.IsNull() && !v.IsUnknown() && v.ValueBool() {
			resp.Diagnostics.AddAttributeError(
				path.Root("custom_block_list_control").AtName("block_yanked_versions"),
				"block_yanked_versions not applicable",
				fmt.Sprintf("block_yanked_versions is not applicable to registry %q. Remove this attribute or set registry to \"cargo\".", registry),
			)
		}
	}

	if registry == "maven" && !model.CustomBlockListControl.IsNull() && !model.CustomBlockListControl.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("custom_block_list_control"),
			"custom_block_list_control not applicable",
			"custom_block_list_control is not applicable to registry \"maven\". Remove this block or use a different registry.",
		)
	}
}

func (r *secureRegistryPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

func (r *secureRegistryPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secureRegistryPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	upsertReq := r.buildUpsertRequest(ctx, &plan, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.client.UpsertRegistryControls(ctx, plan.Registry.ValueString(), upsertReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating secure registry policy", err.Error())
		return
	}

	// For Create, ref state is the plan (no prior state). Controls not in plan stay null.
	r.applyAPIResponseToModel(ctx, &plan, &plan, result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *secureRegistryPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secureRegistryPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.client.GetRegistryControls(ctx, state.Registry.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading secure registry policy", err.Error())
		return
	}

	// Use current state as ref so disabled controls are only tracked if already tracked.
	r.applyAPIResponseToModel(ctx, &state, &state, result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *secureRegistryPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secureRegistryPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state secureRegistryPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build request: include controls from plan; if a control was in state but not in plan, disable it.
	upsertReq := r.buildUpsertRequest(ctx, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.client.UpsertRegistryControls(ctx, plan.Registry.ValueString(), upsertReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating secure registry policy", err.Error())
		return
	}

	// Use plan as ref: controls removed from plan should become null in state.
	r.applyAPIResponseToModel(ctx, &plan, &plan, result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *secureRegistryPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secureRegistryPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteRegistryControls(ctx, state.Registry.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting secure registry policy", err.Error())
		return
	}
}

func (r *secureRegistryPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the registry name (e.g., "npm").
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("registry"), req.ID)...)

	readReq := resource.ReadRequest{State: resp.State}
	readResp := &resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

// buildUpsertRequest builds the PUT request from plan. When a control block was
// in prevState but is now null in plan (user removed it), it is explicitly disabled
// so the backend resets it rather than preserving the old value.
func (r *secureRegistryPolicyResource) buildUpsertRequest(
	ctx context.Context,
	plan *secureRegistryPolicyResourceModel,
	prevState *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) stepsecurityapi.UpsertSecureRegistryControlsRequest {
	req := stepsecurityapi.UpsertSecureRegistryControlsRequest{}

	// cooldown_control
	if !plan.CooldownControl.IsNull() {
		var m cooldownControlModel
		diags.Append(plan.CooldownControl.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		ctrl := &stepsecurityapi.CooldownPeriodControl{
			Enabled:      m.Enabled.ValueBool(),
			PeriodInDays: int(m.PeriodInDays.ValueInt64()),
		}
		if !m.ExemptionList.IsNull() {
			var exemptions []string
			diags.Append(m.ExemptionList.ElementsAs(ctx, &exemptions, false)...)
			ctrl.ExemptionList = exemptions
		}
		req.CooldownPeriod = ctrl
	} else if prevState != nil && !prevState.CooldownControl.IsNull() {
		// Control was previously tracked — disable it on the backend.
		req.CooldownPeriod = &stepsecurityapi.CooldownPeriodControl{Enabled: false, PeriodInDays: 1}
	}

	// compromised_packages_control
	if !plan.CompromisedPackagesControl.IsNull() {
		var m compromisedPackagesControlModel
		diags.Append(plan.CompromisedPackagesControl.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		req.CompromisedPackages = &stepsecurityapi.CompromisedPackagesControl{
			Enabled: m.Enabled.ValueBool(),
		}
	} else if prevState != nil && !prevState.CompromisedPackagesControl.IsNull() {
		req.CompromisedPackages = &stepsecurityapi.CompromisedPackagesControl{Enabled: false}
	}

	// typosquatting_control
	if !plan.TyposquattingControl.IsNull() {
		var m typosquattingControlModel
		diags.Append(plan.TyposquattingControl.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		ctrl := &stepsecurityapi.TyposquattingControl{
			Enabled: m.Enabled.ValueBool(),
		}
		if !m.ExemptionList.IsNull() {
			var exemptions []string
			diags.Append(m.ExemptionList.ElementsAs(ctx, &exemptions, false)...)
			ctrl.Whitelist = exemptions
		}
		req.Typosquatting = ctrl
	} else if prevState != nil && !prevState.TyposquattingControl.IsNull() {
		// Control was previously tracked — disable it on the backend.
		req.Typosquatting = &stepsecurityapi.TyposquattingControl{Enabled: false, Whitelist: []string{}}
	}

	// custom_block_list_control
	if !plan.CustomBlockListControl.IsNull() {
		var m customBlockListControlModel
		diags.Append(plan.CustomBlockListControl.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		ctrl := &stepsecurityapi.CustomBlockListControl{
			Enabled: m.Enabled.ValueBool(),
		}
		if !m.Patterns.IsNull() {
			var patterns []string
			diags.Append(m.Patterns.ElementsAs(ctx, &patterns, false)...)
			ctrl.Patterns = patterns
		}
		if !m.BlockPseudoVersions.IsNull() && !m.BlockPseudoVersions.IsUnknown() {
			var pseudo []string
			diags.Append(m.BlockPseudoVersions.ElementsAs(ctx, &pseudo, false)...)
			ctrl.BlockPseudoVersions = pseudo
		}
		ctrl.BlockYankedVersions = m.BlockYankedVersions.ValueBool()
		req.CustomBlockList = ctrl
	} else if prevState != nil && !prevState.CustomBlockListControl.IsNull() {
		req.CustomBlockList = &stepsecurityapi.CustomBlockListControl{Enabled: false, Patterns: []string{}}
	}

	// npm_settings — always send the current desired value when present in plan; on
	// removal from config, reset to false so the backend doesn't keep a stale value.
	if !plan.NpmSettings.IsNull() {
		var m npmSettingsModel
		diags.Append(plan.NpmSettings.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		ctrl := &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: m.RewriteTarballURLs.ValueBool()}
		var prev npmSettingsModel
		if prevState != nil && !prevState.NpmSettings.IsNull() {
			diags.Append(prevState.NpmSettings.As(ctx, &prev, basetypes.ObjectAsOptions{})...)
		}
		ctrl.BlockMessageTemplate = templateForUpsert(m.BlockMessageTemplate, prev.BlockMessageTemplate)
		ctrl.HiddenVersionsNoticeTemplate = templateForUpsert(m.HiddenVersionsNoticeTemplate, prev.HiddenVersionsNoticeTemplate)
		req.NpmSettings = ctrl
	} else if prevState != nil && !prevState.NpmSettings.IsNull() {
		// Block removed from config: reset everything so the backend keeps no stale value.
		empty := ""
		req.NpmSettings = &stepsecurityapi.NpmSettingsControl{
			RewriteTarballURLs:           false,
			BlockMessageTemplate:         &empty,
			HiddenVersionsNoticeTemplate: &empty,
		}
	}

	// go_settings: same shape as npm_settings: send the planned value, reset on removal.
	if !plan.GoSettings.IsNull() {
		var m goSettingsModel
		diags.Append(plan.GoSettings.As(ctx, &m, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return req
		}
		req.GoSettings = &stepsecurityapi.GoSettingsControl{ProxyChecksumDB: m.ProxyChecksumDB.ValueBool()}
	} else if prevState != nil && !prevState.GoSettings.IsNull() {
		req.GoSettings = &stepsecurityapi.GoSettingsControl{ProxyChecksumDB: false}
	}

	return req
}

// templateForUpsert maps a planned template to the request value. The backend keeps the
// stored template when the field is omitted and clears it on "", so a template that was
// set in prior state but is now null must be sent as an explicit empty string.
func templateForUpsert(planned, prev types.String) *string {
	if !planned.IsNull() && !planned.IsUnknown() {
		v := planned.ValueString()
		return &v
	}
	if !prev.IsNull() && !prev.IsUnknown() {
		empty := ""
		return &empty
	}
	return nil
}

// templateOrNull returns null for an unset/empty API template so state matches a config
// that omits the attribute.
func templateOrNull(v *string) types.String {
	if v == nil || *v == "" {
		return types.StringNull()
	}
	return types.StringValue(*v)
}

// templateFromAPI is templateOrNull, except that an empty or absent API value stays ""
// when the reference value is an explicit "".
func templateFromAPI(v *string, ref types.String) types.String {
	if out := templateOrNull(v); !out.IsNull() {
		return out
	}
	if !ref.IsNull() && !ref.IsUnknown() && ref.ValueString() == "" {
		return types.StringValue("")
	}
	return types.StringNull()
}

// applyAPIResponseToModel writes API response fields into model.
// ref is used to determine which disabled controls were already being tracked
// (and should therefore remain in state rather than becoming null).
func (r *secureRegistryPolicyResource) applyAPIResponseToModel(
	ctx context.Context,
	ref *secureRegistryPolicyResourceModel,
	model *secureRegistryPolicyResourceModel,
	controls *stepsecurityapi.SecureRegistryControls,
	diags *diag.Diagnostics,
) {
	model.Registry = types.StringValue(controls.Registry)

	// cooldown_control
	model.CooldownControl = r.buildCooldownControlObject(ctx, controls.CooldownPeriod, ref, diags)

	// compromised_packages_control
	model.CompromisedPackagesControl = r.buildCompromisedPackagesControlObject(controls.CompromisedPackages, ref, diags)

	// typosquatting_control
	model.TyposquattingControl = r.buildTyposquattingControlObject(ctx, controls.Typosquatting, ref, diags)

	// custom_block_list_control
	model.CustomBlockListControl = r.buildCustomBlockListControlObject(ctx, controls.CustomBlockList, ref, diags)

	// npm_settings
	model.NpmSettings = r.buildNpmSettingsObject(controls.NpmSettings, ref, diags)

	// go_settings
	model.GoSettings = r.buildGoSettingsObject(controls.GoSettings, ref, diags)
}

// buildCooldownControlObject converts the API cooldown period to a Terraform object.
// If the control is disabled and ref did not track it, null is returned so the
// user's state stays clean.
func (r *secureRegistryPolicyResource) buildCooldownControlObject(
	ctx context.Context,
	ctrl *stepsecurityapi.CooldownPeriodControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(cooldownControlAttrTypes)
	}

	refTracking := ref != nil && !ref.CooldownControl.IsNull()
	if !ctrl.Enabled && !refTracking {
		// Disabled and not previously tracked — treat as not configured.
		return types.ObjectNull(cooldownControlAttrTypes)
	}

	var exemptionListVal attr.Value
	if len(ctrl.ExemptionList) > 0 {
		vals := make([]attr.Value, len(ctrl.ExemptionList))
		for i, v := range ctrl.ExemptionList {
			vals[i] = types.StringValue(v)
		}
		setVal, setDiags := types.SetValue(types.StringType, vals)
		diags.Append(setDiags...)
		exemptionListVal = setVal
	} else {
		// Preserve existing exemption_list value if it was an explicit empty set.
		if refTracking {
			var existingM cooldownControlModel
			if diag := ref.CooldownControl.As(ctx, &existingM, basetypes.ObjectAsOptions{}); !diag.HasError() && !existingM.ExemptionList.IsNull() {
				emptySet, emptyDiags := types.SetValue(types.StringType, []attr.Value{})
				diags.Append(emptyDiags...)
				exemptionListVal = emptySet
			} else {
				exemptionListVal = types.SetNull(types.StringType)
			}
		} else {
			exemptionListVal = types.SetNull(types.StringType)
		}
	}

	obj, objDiags := types.ObjectValue(cooldownControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(ctrl.Enabled),
		"period_in_days": types.Int64Value(int64(ctrl.PeriodInDays)),
		"exemption_list": exemptionListVal,
	})
	diags.Append(objDiags...)
	return obj
}

// buildCompromisedPackagesControlObject converts the API compromised packages control to a Terraform object.
func (r *secureRegistryPolicyResource) buildCompromisedPackagesControlObject(
	ctrl *stepsecurityapi.CompromisedPackagesControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(compromisedPackagesControlAttrTypes)
	}

	refTracking := ref != nil && !ref.CompromisedPackagesControl.IsNull()
	if !ctrl.Enabled && !refTracking {
		return types.ObjectNull(compromisedPackagesControlAttrTypes)
	}

	obj, objDiags := types.ObjectValue(compromisedPackagesControlAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(ctrl.Enabled),
	})
	diags.Append(objDiags...)
	return obj
}

// buildTyposquattingControlObject converts the API typosquatting control to a Terraform object.
// If the control is disabled and ref did not track it, null is returned so the
// user's state stays clean.
func (r *secureRegistryPolicyResource) buildTyposquattingControlObject(
	ctx context.Context,
	ctrl *stepsecurityapi.TyposquattingControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(typosquattingControlAttrTypes)
	}

	refTracking := ref != nil && !ref.TyposquattingControl.IsNull()
	if !ctrl.Enabled && !refTracking {
		// Disabled and not previously tracked — treat as not configured.
		return types.ObjectNull(typosquattingControlAttrTypes)
	}

	var exemptionListVal attr.Value
	if len(ctrl.Whitelist) > 0 {
		vals := make([]attr.Value, len(ctrl.Whitelist))
		for i, v := range ctrl.Whitelist {
			vals[i] = types.StringValue(v)
		}
		setVal, setDiags := types.SetValue(types.StringType, vals)
		diags.Append(setDiags...)
		exemptionListVal = setVal
	} else {
		// Preserve existing exemption_list value if it was an explicit empty set.
		if refTracking {
			var existingM typosquattingControlModel
			if diag := ref.TyposquattingControl.As(ctx, &existingM, basetypes.ObjectAsOptions{}); !diag.HasError() && !existingM.ExemptionList.IsNull() {
				emptySet, emptyDiags := types.SetValue(types.StringType, []attr.Value{})
				diags.Append(emptyDiags...)
				exemptionListVal = emptySet
			} else {
				exemptionListVal = types.SetNull(types.StringType)
			}
		} else {
			exemptionListVal = types.SetNull(types.StringType)
		}
	}

	obj, objDiags := types.ObjectValue(typosquattingControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(ctrl.Enabled),
		"exemption_list": exemptionListVal,
	})
	diags.Append(objDiags...)
	return obj
}

// buildCustomBlockListControlObject converts the API custom block list control to a Terraform object.
// If the control is disabled and ref did not track it, null is returned so the
// user's state stays clean.
func (r *secureRegistryPolicyResource) buildCustomBlockListControlObject(
	ctx context.Context,
	ctrl *stepsecurityapi.CustomBlockListControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(customBlockListControlAttrTypes)
	}

	refTracking := ref != nil && !ref.CustomBlockListControl.IsNull()
	if !ctrl.Enabled && !refTracking && len(ctrl.BlockPseudoVersions) == 0 && !ctrl.BlockYankedVersions {
		// Disabled and not previously tracked — treat as not configured.
		return types.ObjectNull(customBlockListControlAttrTypes)
	}

	var patternsVal attr.Value
	if len(ctrl.Patterns) > 0 {
		vals := make([]attr.Value, len(ctrl.Patterns))
		for i, v := range ctrl.Patterns {
			vals[i] = types.StringValue(v)
		}
		setVal, setDiags := types.SetValue(types.StringType, vals)
		diags.Append(setDiags...)
		patternsVal = setVal
	} else {
		// Preserve existing patterns value if it was an explicit empty set.
		if refTracking {
			var existingM customBlockListControlModel
			if diag := ref.CustomBlockListControl.As(ctx, &existingM, basetypes.ObjectAsOptions{}); !diag.HasError() && !existingM.Patterns.IsNull() {
				emptySet, emptyDiags := types.SetValue(types.StringType, []attr.Value{})
				diags.Append(emptyDiags...)
				patternsVal = emptySet
			} else {
				patternsVal = types.SetNull(types.StringType)
			}
		} else {
			patternsVal = types.SetNull(types.StringType)
		}
	}

	pseudoVal := types.SetNull(types.StringType)
	if len(ctrl.BlockPseudoVersions) > 0 {
		vals := make([]attr.Value, len(ctrl.BlockPseudoVersions))
		for i, v := range ctrl.BlockPseudoVersions {
			vals[i] = types.StringValue(v)
		}
		setVal, setDiags := types.SetValue(types.StringType, vals)
		diags.Append(setDiags...)
		pseudoVal = setVal
	} else if refTracking {
		// Preserve an explicit empty set from config so it doesn't show as drift.
		var existingM customBlockListControlModel
		if d := ref.CustomBlockListControl.As(ctx, &existingM, basetypes.ObjectAsOptions{}); !d.HasError() && !existingM.BlockPseudoVersions.IsNull() && !existingM.BlockPseudoVersions.IsUnknown() {
			emptySet, emptyDiags := types.SetValue(types.StringType, []attr.Value{})
			diags.Append(emptyDiags...)
			pseudoVal = emptySet
		}
	}

	obj, objDiags := types.ObjectValue(customBlockListControlAttrTypes, map[string]attr.Value{
		"enabled":               types.BoolValue(ctrl.Enabled),
		"patterns":              patternsVal,
		"block_pseudo_versions": pseudoVal,
		"block_yanked_versions": types.BoolValue(ctrl.BlockYankedVersions),
	})
	diags.Append(objDiags...)
	return obj
}

// buildNpmSettingsObject converts the API npm settings to a Terraform object.
// If the setting is off (false) and ref did not track it, null is returned so the
// user's state stays clean — mirrors the enabled/disabled null-preservation rule
// used by the other controls, treating RewriteTarballURLs as the pseudo-enabled signal.
func (r *secureRegistryPolicyResource) buildNpmSettingsObject(
	ctrl *stepsecurityapi.NpmSettingsControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(npmSettingsAttrTypes)
	}

	refTracking := ref != nil && !ref.NpmSettings.IsNull()
	hasTemplates := templateOrNull(ctrl.BlockMessageTemplate).ValueString() != "" ||
		templateOrNull(ctrl.HiddenVersionsNoticeTemplate).ValueString() != ""
	if !ctrl.RewriteTarballURLs && !hasTemplates && !refTracking {
		return types.ObjectNull(npmSettingsAttrTypes)
	}

	// An explicit "" in config clears the template on the backend, which then reports it
	// as absent. Keep "" in state when the reference (plan or prior state) holds "" so
	// Terraform does not see a changed value after apply or a perpetual diff.
	var refBlock, refNotice types.String = types.StringNull(), types.StringNull()
	if refTracking && !ref.NpmSettings.IsUnknown() {
		var m npmSettingsModel
		if d := ref.NpmSettings.As(context.Background(), &m, basetypes.ObjectAsOptions{}); !d.HasError() {
			refBlock, refNotice = m.BlockMessageTemplate, m.HiddenVersionsNoticeTemplate
		}
	}

	obj, objDiags := types.ObjectValue(npmSettingsAttrTypes, map[string]attr.Value{
		"rewrite_tarball_urls":            types.BoolValue(ctrl.RewriteTarballURLs),
		"block_message_template":          templateFromAPI(ctrl.BlockMessageTemplate, refBlock),
		"hidden_versions_notice_template": templateFromAPI(ctrl.HiddenVersionsNoticeTemplate, refNotice),
	})
	diags.Append(objDiags...)
	return obj
}

// buildGoSettingsObject converts the API go settings to a Terraform object. Mirrors
// buildNpmSettingsObject: when the setting is off and ref did not track it, null is
// returned so state stays clean.
func (r *secureRegistryPolicyResource) buildGoSettingsObject(
	ctrl *stepsecurityapi.GoSettingsControl,
	ref *secureRegistryPolicyResourceModel,
	diags *diag.Diagnostics,
) types.Object {
	if ctrl == nil {
		return types.ObjectNull(goSettingsAttrTypes)
	}

	refTracking := ref != nil && !ref.GoSettings.IsNull()
	if !ctrl.ProxyChecksumDB && !refTracking {
		return types.ObjectNull(goSettingsAttrTypes)
	}

	obj, objDiags := types.ObjectValue(goSettingsAttrTypes, map[string]attr.Value{
		"proxy_checksum_db": types.BoolValue(ctrl.ProxyChecksumDB),
	})
	diags.Append(objDiags...)
	return obj
}
