package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &githubPolicyStoreResource{}
	_ resource.ResourceWithConfigure      = &githubPolicyStoreResource{}
	_ resource.ResourceWithImportState    = &githubPolicyStoreResource{}
	_ resource.ResourceWithValidateConfig = &githubPolicyStoreResource{}
)

// NewOrderResource is a helper function to simplify the provider implementation.
func NewGithubPolicyStoreResource() resource.Resource {
	return &githubPolicyStoreResource{}
}

// orderResource is the resource implementation.
type githubPolicyStoreResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *githubPolicyStoreResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_policy_store"
}

// Schema defines the schema for the resource.
func (r *githubPolicyStoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the policy store. This is combination of owner and policy name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "Github Organization(owner) name",
			},
			"policy_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy",
			},
			"egress_policy": schema.StringAttribute{
				Required:    true,
				Description: "Egress policy mode. Can be 'audit' or 'block'",
			},
			"allowed_endpoints": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(
					types.ListValueMust(
						types.StringType,
						[]attr.Value{
							types.StringValue("github.com:443"),
						},
					),
				),
				PlanModifiers: []planmodifier.List{
					suppressAllowedEndpointsDefaultWhenDeniedSetModifier{},
				},
				Description: "List of allowed endpoints. This specifies list of enpoints to allow when egress policy is set to 'block' mode",
			},
			"denied_endpoints": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: setdefault.StaticValue(
					types.SetValueMust(
						types.StringType,
						[]attr.Value{},
					),
				),
				Description: "Set of denied endpoints (hostnames only, e.g. 'evil.example.com'). Unlike allowed_endpoints, a port is not required and has no effect if included. This specifies endpoints to deny when egress policy is set to 'block' mode. Cannot be set together with allowed_endpoints.",
			},
			"disable_telemetry": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables telemetry collection.",
			},
			"disable_sudo": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables sudo access for HardenRunner agent",
			},
			"disable_file_monitoring": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables file monitoring",
			},
			"lockdown": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Lockdown configuration. When enabled, stops the job if a selected detection fires.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable lockdown mode.",
					},
					"privileged_container": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Trigger lockdown on Privileged-Container detection.",
					},
					"runner_worker_memory_read": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Trigger lockdown on Runner-Worker-Memory-Read detection.",
					},
					"reverse_shell": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Trigger lockdown on Reverse-Shell detection.",
					},
				},
			},
		},
	}
}

// suppressAllowedEndpointsDefaultWhenDeniedSetModifier prevents allowed_endpoints
// from resolving to its ["github.com:443"] default when the user configured
// denied_endpoints instead. Without this, a config that only sets
// denied_endpoints would still plan allowed_endpoints as its default, and the
// API rejects any request where both are non-empty with "allowed_endpoints and
// denied_endpoints cannot both be present" - even though the user never set
// allowed_endpoints themselves. If the user explicitly configures
// allowed_endpoints, this modifier does nothing and ValidateConfig's conflict
// check applies as normal.
type suppressAllowedEndpointsDefaultWhenDeniedSetModifier struct{}

func (m suppressAllowedEndpointsDefaultWhenDeniedSetModifier) Description(_ context.Context) string {
	return "Avoids defaulting allowed_endpoints when denied_endpoints is configured."
}

func (m suppressAllowedEndpointsDefaultWhenDeniedSetModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m suppressAllowedEndpointsDefaultWhenDeniedSetModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if !req.ConfigValue.IsNull() {
		return
	}

	var deniedEndpoints types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("denied_endpoints"), &deniedEndpoints)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if deniedEndpoints.IsUnknown() {
		resp.PlanValue = types.ListUnknown(types.StringType)
		return
	}

	if !deniedEndpoints.IsNull() && len(deniedEndpoints.Elements()) > 0 {
		resp.PlanValue = types.ListValueMust(types.StringType, []attr.Value{})
	}
}

// Configure adds the provider configured client to the resource.
func (r *githubPolicyStoreResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)

	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// ValidateConfig implements resource.ResourceWithValidateConfig.
func (r *githubPolicyStoreResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model githubPolicyStoreModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Defer validation until both are fully known — avoids erroring on
	// partially-unknown config (e.g. values derived from other resources).
	if model.AllowedEndpoints.IsUnknown() || model.DeniedEndpoints.IsUnknown() {
		return
	}

	allowedLen := 0
	if !model.AllowedEndpoints.IsNull() {
		allowedLen = len(model.AllowedEndpoints.Elements())
	}
	deniedLen := 0
	if !model.DeniedEndpoints.IsNull() {
		deniedLen = len(model.DeniedEndpoints.Elements())
	}

	if allowedLen > 0 && deniedLen > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("denied_endpoints"),
			"Conflicting endpoint lists",
			"`allowed_endpoints` and `denied_endpoints` cannot both be set. Use one or the other.",
		)
	}
}

type githubPolicyStoreModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	PolicyName            types.String `tfsdk:"policy_name"`
	EgressPolicy          types.String `tfsdk:"egress_policy"`
	AllowedEndpoints      types.List   `tfsdk:"allowed_endpoints"`
	DeniedEndpoints       types.Set    `tfsdk:"denied_endpoints"`
	DisableTelemetry      types.Bool   `tfsdk:"disable_telemetry"`
	DisableSudo           types.Bool   `tfsdk:"disable_sudo"`
	DisableFileMonitoring types.Bool   `tfsdk:"disable_file_monitoring"`
	Lockdown              types.Object `tfsdk:"lockdown"`
}

type lockdownConfigModel struct {
	Enabled                types.Bool `tfsdk:"enabled"`
	PrivilegedContainer    types.Bool `tfsdk:"privileged_container"`
	RunnerWorkerMemoryRead types.Bool `tfsdk:"runner_worker_memory_read"`
	ReverseShell           types.Bool `tfsdk:"reverse_shell"`
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPolicyStoreResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	id := req.ID

	// Split the ID into owner and policy name
	splitted := strings.Split(id, ":::")
	if len(splitted) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected owner:::policy_name, got: %s", id),
		)
		return
	}

	// Set the owner/policy name in the state
	owner := splitted[0]
	policyName := splitted[1]
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_name"), policyName)...)

	// Now call Read to populate the rest of the state
	readReq := resource.ReadRequest{
		State: resp.State,
	}
	readResp := &resource.ReadResponse{
		State: resp.State,
	}

	r.Read(ctx, readReq, readResp)

	// Copy any diagnostics and updated state from Read
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubPolicyStoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPolicyStoreModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.getGitHubPolicyStorePolicy(ctx, plan)
	if err := r.client.CreateGitHubPolicyStorePolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError(
			"Failed to create policy",
			fmt.Sprintf("Error creating policy: %s", err),
		)
		return
	}

	// get the policy and update state
	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, plan.Owner.ValueString(), plan.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy after create",
			fmt.Sprintf("Error reading policy after create: %s", err),
		)
		return
	}

	// update the state
	r.updateGitHubPolicyStorePolicyState(policy, &plan)

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Read refreshes the Terraform state with the latest data.
func (r *githubPolicyStoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy",
			fmt.Sprintf("Error reading policy: %s", err),
		)
		return
	}

	// update the state
	r.updateGitHubPolicyStorePolicyState(policy, &state)
	// Set state to fully populated data
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPolicyStoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPolicyStoreModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.getGitHubPolicyStorePolicy(ctx, plan)
	if err := r.client.CreateGitHubPolicyStorePolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError(
			"Failed to update policy",
			fmt.Sprintf("Error updating policy: %s", err),
		)
		return
	}

	// get the policy and update state
	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, plan.Owner.ValueString(), plan.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy after update",
			fmt.Sprintf("Error reading policy after update: %s", err),
		)
		return
	}

	// update the state
	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.updateGitHubPolicyStorePolicyState(policy, &state)

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubPolicyStoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString()); err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete policy",
			fmt.Sprintf("Error deleting policy: %s", err),
		)
		return
	}
}

func (r *githubPolicyStoreResource) updateGitHubPolicyStorePolicyState(policy *stepsecurityapi.GitHubPolicyStorePolicy, state *githubPolicyStoreModel) {

	var allowedEndpoints []attr.Value
	for _, endpoint := range policy.AllowedEndpoints {
		allowedEndpoints = append(allowedEndpoints, types.StringValue(endpoint))
	}

	var deniedEndpoints []attr.Value
	for _, endpoint := range policy.DeniedEndpoints {
		deniedEndpoints = append(deniedEndpoints, types.StringValue(endpoint))
	}

	state.ID = types.StringValue(policy.Owner + ":::" + policy.PolicyName)
	state.Owner = types.StringValue(policy.Owner)
	state.PolicyName = types.StringValue(policy.PolicyName)
	state.AllowedEndpoints = types.ListValueMust(
		types.StringType,
		allowedEndpoints,
	)
	state.DeniedEndpoints = types.SetValueMust(
		types.StringType,
		deniedEndpoints,
	)
	state.EgressPolicy = types.StringValue(policy.EgressPolicy)
	state.DisableTelemetry = types.BoolValue(policy.DisableTelemetry)
	state.DisableSudo = types.BoolValue(policy.DisableSudo)
	state.DisableFileMonitoring = types.BoolValue(policy.DisableFileMonitoring)

	lockdownAttrTypes := map[string]attr.Type{
		"enabled":                   types.BoolType,
		"privileged_container":      types.BoolType,
		"runner_worker_memory_read": types.BoolType,
		"reverse_shell":             types.BoolType,
	}
	if policy.Lockdown != nil {
		detectionSet := make(map[string]bool)
		for _, d := range policy.Lockdown.Detections {
			detectionSet[d] = true
		}
		lockdownObj, _ := types.ObjectValue(lockdownAttrTypes, map[string]attr.Value{
			"enabled":                   types.BoolValue(policy.Lockdown.Enabled),
			"privileged_container":      types.BoolValue(detectionSet["Privileged-Container"]),
			"runner_worker_memory_read": types.BoolValue(detectionSet["Runner-Worker-Memory-Read"]),
			"reverse_shell":             types.BoolValue(detectionSet["Reverse-Shell"]),
		})
		state.Lockdown = lockdownObj
	} else {
		state.Lockdown = types.ObjectNull(lockdownAttrTypes)
	}
}

func (r *githubPolicyStoreResource) getGitHubPolicyStorePolicy(ctx context.Context, plan githubPolicyStoreModel) *stepsecurityapi.GitHubPolicyStorePolicy {
	var allowedEndpoints []string
	for _, ep := range plan.AllowedEndpoints.Elements() {
		allowedEndpoints = append(allowedEndpoints, ep.(types.String).ValueString())
	}

	var deniedEndpoints []string
	for _, ep := range plan.DeniedEndpoints.Elements() {
		deniedEndpoints = append(deniedEndpoints, ep.(types.String).ValueString())
	}

	var lockdownConfig *stepsecurityapi.LockdownConfig
	if !plan.Lockdown.IsNull() && !plan.Lockdown.IsUnknown() {
		var lm lockdownConfigModel
		plan.Lockdown.As(ctx, &lm, basetypes.ObjectAsOptions{})

		var detections []string
		if lm.PrivilegedContainer.ValueBool() {
			detections = append(detections, "Privileged-Container")
		}
		if lm.RunnerWorkerMemoryRead.ValueBool() {
			detections = append(detections, "Runner-Worker-Memory-Read")
		}
		if lm.ReverseShell.ValueBool() {
			detections = append(detections, "Reverse-Shell")
		}

		lockdownConfig = &stepsecurityapi.LockdownConfig{
			Enabled:    lm.Enabled.ValueBool(),
			Detections: detections,
		}
	}

	return &stepsecurityapi.GitHubPolicyStorePolicy{
		Owner:                 plan.Owner.ValueString(),
		PolicyName:            plan.PolicyName.ValueString(),
		AllowedEndpoints:      allowedEndpoints,
		DeniedEndpoints:       deniedEndpoints,
		EgressPolicy:          plan.EgressPolicy.ValueString(),
		DisableTelemetry:      plan.DisableTelemetry.ValueBool(),
		DisableSudo:           plan.DisableSudo.ValueBool(),
		DisableFileMonitoring: plan.DisableFileMonitoring.ValueBool(),
		Lockdown:              lockdownConfig,
	}
}
