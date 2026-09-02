package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &roleResource{}
	_ resource.ResourceWithConfigure   = &roleResource{}
	_ resource.ResourceWithImportState = &roleResource{}
)

// NewRoleResource is the factory the provider registers.
func NewRoleResource() resource.Resource {
	return &roleResource{}
}

type roleResource struct {
	client stepsecurityapi.Client
}

// roleModel maps the Terraform schema to a Go type.
type roleModel struct {
	ID          types.String       `tfsdk:"id"`
	Name        types.String       `tfsdk:"name"`
	Description types.String       `tfsdk:"description"`
	Permissions []rolePermissionTF `tfsdk:"permissions"`
}

type rolePermissionTF struct {
	Resource types.String `tfsdk:"resource"`
	Action   types.String `tfsdk:"action"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Defines a custom role for the configured customer. The role is built from a list of " +
			"(resource, action) permission pairs and can then be assigned to one or more `stepsecurity_user` " +
			"resources via the `policies` block. System roles `admin` and `auditor` are NOT manageable through " +
			"this resource — use `stepsecurity_user.policies.role = \"admin\"` (or `auditor`) to assign them.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Stable UUID assigned by the API. Renaming the role preserves this ID and " +
					"automatically rewrites all existing user assignments.",
			},
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-z][a-z0-9_-]{1,49}$`),
						"role name must be lowercase, start with a letter, and contain only letters, digits, hyphens, or underscores (2-50 chars)",
					),
					stringvalidator.NoneOfCaseInsensitive("admin", "auditor"),
				},
				Description: "Lowercase role name shown in the console. Cannot collide with the built-in " +
					"`admin` or `auditor`. Renaming is allowed and triggers an in-place rewrite of all " +
					"user assignments referencing the old name.",
			},
			"description": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(256),
				},
				Description: "Free-form description shown next to the role in the console. Max 256 chars.",
			},
			"permissions": schema.ListNestedAttribute{
				Required:   true,
				Validators: []validator.List{
					// Empty permissions list is rejected by the API; surface
					// it during plan so the user fixes it before apply.
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"resource": schema.StringAttribute{
							Required: true,
							Description: "Permission resource name. Must be a valid catalog entry — " +
								"see `GET /v1/{customer}/permissions` or the console role-edit dialog " +
								"for the canonical list (e.g. `detections`, `run-policies`, `developer-mdm`).",
						},
						"action": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf("read", "write"),
							},
							Description: "`read` or `write`. Some resources expose only `read` " +
								"(e.g. `audit-logs`, `action-secrets`); the API will reject invalid pairings.",
						},
					},
				},
				Description: "Set of (resource, action) permission pairs that compose this role. Order is " +
					"insignificant — drift detection compares the unordered set.",
			},
		},
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "creating stepsecurity custom role", map[string]any{
		"name":             plan.Name.ValueString(),
		"permission_count": len(plan.Permissions),
	})

	created, err := r.client.CreateRole(ctx, stepsecurityapi.CreateRoleRequest{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Permissions: toAPIPermissions(plan.Permissions),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to Create StepSecurity Role", err.Error())
		return
	}

	r.applyAPIToState(ctx, created, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	role, err := r.client.GetRole(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read StepSecurity Role", err.Error())
		return
	}

	r.applyAPIToState(ctx, role, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "updating stepsecurity custom role", map[string]any{
		"role_id":  state.ID.ValueString(),
		"old_name": state.Name.ValueString(),
		"new_name": plan.Name.ValueString(),
	})

	updated, err := r.client.UpdateRole(ctx, state.ID.ValueString(), stepsecurityapi.UpdateRoleRequest{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Permissions: toAPIPermissions(plan.Permissions),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to Update StepSecurity Role", err.Error())
		return
	}

	r.applyAPIToState(ctx, updated, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteRole(ctx, state.ID.ValueString()); err != nil {
		// The API returns 409 Conflict with the list of users still holding
		// the role. Bubble the error up unchanged so terraform shows it.
		resp.Diagnostics.AddError(
			"Unable to Delete StepSecurity Role",
			"The API rejected the delete. If the role is still assigned to users, "+
				"update or destroy the affected stepsecurity_user resources first.\n\n"+
				err.Error(),
		)
		return
	}
}

// applyAPIToState copies the API-returned role into the Terraform state, but
// preserves the user's planned permission ordering when the API set is the
// same — terraform's drift detection on a list is order-sensitive even though
// permissions are semantically a set.
func (r *roleResource) applyAPIToState(_ context.Context, role *stepsecurityapi.Role, state *roleModel) {
	state.ID = types.StringValue(role.ID)
	state.Name = types.StringValue(role.Name)
	if role.Description == "" {
		state.Description = types.StringNull()
	} else {
		state.Description = types.StringValue(role.Description)
	}
	if !permissionsMatchAsSets(state.Permissions, role.Permissions) {
		state.Permissions = fromAPIPermissions(role.Permissions)
	}
}

func toAPIPermissions(in []rolePermissionTF) []stepsecurityapi.Permission {
	out := make([]stepsecurityapi.Permission, 0, len(in))
	for _, p := range in {
		out = append(out, stepsecurityapi.Permission{
			Resource: p.Resource.ValueString(),
			Action:   p.Action.ValueString(),
		})
	}
	return out
}

func fromAPIPermissions(in []stepsecurityapi.Permission) []rolePermissionTF {
	out := make([]rolePermissionTF, 0, len(in))
	for _, p := range in {
		out = append(out, rolePermissionTF{
			Resource: types.StringValue(p.Resource),
			Action:   types.StringValue(p.Action),
		})
	}
	return out
}

// permissionsMatchAsSets returns true when state and api describe the same
// (resource, action) set, regardless of ordering. Used to suppress no-op
// drift when the API returns permissions in a different order than the plan.
func permissionsMatchAsSets(state []rolePermissionTF, api []stepsecurityapi.Permission) bool {
	if len(state) != len(api) {
		return false
	}
	seen := make(map[string]struct{}, len(api))
	for _, p := range api {
		seen[p.Resource+"\x00"+p.Action] = struct{}{}
	}
	for _, p := range state {
		key := p.Resource.ValueString() + "\x00" + p.Action.ValueString()
		if _, ok := seen[key]; !ok {
			return false
		}
	}
	return true
}
