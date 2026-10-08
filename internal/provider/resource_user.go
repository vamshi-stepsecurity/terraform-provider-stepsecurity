package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &userResource{}
	_ resource.ResourceWithConfigure   = &userResource{}
	_ resource.ResourceWithModifyPlan  = &userResource{}
	_ resource.ResourceWithImportState = &userResource{}
)

// NewUserResource is a helper function to simplify the provider implementation.
func NewUserResource() resource.Resource {
	return &userResource{}
}

// orderResource is the resource implementation.
type userResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *userResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

// Configure adds the provider configured client to the resource.
func (r *userResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Schema defines the schema for the resource.
func (r *userResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The ID of the user",
			},
			"user_name": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The GitHub username of the user. This is required for adding users with auth_type = GitHub",
			},
			"email": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The email of the user. This is required for adding users with auth_type = SSO/Local",
			},
			"email_suffix": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The email suffix of the user. It is used for providing access to all users with a specific email suffix.",
			},
			"sso_group": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "SSO Group name through which users get access to. This is typically group name defined in SSO providers like Okta, Google Workspace, Auth0, etc.",
			},
			"auth_type": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The authentication type of the user. Valid values are 'Github', 'SSO', 'Local'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Github", "SSO", "Local"),
				},
			},
			"policies": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Required:    true,
							Description: "The CI/CD platform type",
							Validators: []validator.String{
								stringvalidator.OneOf("github", "*"),
							},
						},
						"role": schema.StringAttribute{
							Required:    true,
							Description: "The role of the user. Either a built-in role (`admin` or `auditor`) or the name of a custom role defined with the `stepsecurity_role` resource.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"scope": schema.StringAttribute{
							Required:    true,
							Description: "The permission scope of the policy.",
							Validators: []validator.String{
								stringvalidator.OneOf("customer", "organization", "repository", "group", "project"),
							},
						},
						"organization": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Github organization name that the user has to access (required only when type = 'github' and scope = 'organization' or 'repository' )",
						},
						"repos": schema.ListAttribute{
							ElementType: types.StringType,
							Description: "List of Github repositories that the user has to access (required only when type = 'github' and scope = 'repository')",
							Computed:    true,
							Optional:    true,
						},
						"group": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Group name that the user has to access (required only when type = 'gitlab' and scope = 'group' or 'project')",
						},
						"projects": schema.ListAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Computed:    true,
							Description: "List of projects that the user has to access (required only when type = 'gitlab' and scope = 'project')",
						},
					},
				},
			},
		},
	}
}

func (r *userResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip if this is a delete operation
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan userModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	modified := false
	if plan.Policies != nil {
		for index, policy := range plan.Policies {
			if policy.Scope.ValueString() == "customer" {
				switch policy.Type.ValueString() {
				case "*":
					policy.Organization = types.StringValue("*")

					// Create types.List for repos
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList

					policy.Group = types.StringValue("*")

					// Create types.List for projects
					projectElements := []attr.Value{types.StringValue("*")}
					projectsList, _ := types.ListValue(types.StringType, projectElements)
					policy.Projects = projectsList

					modified = true
				case "github":
					policy.Organization = types.StringValue("*")

					// Create types.List for repos
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList

					policy.Group = basetypes.NewStringNull()
					emptyProjectsList, _ := types.ListValue(types.StringType, []attr.Value{})
					policy.Projects = emptyProjectsList

					modified = true
				case "gitlab":
					policy.Group = types.StringValue("*")

					// Create types.List for projects
					projectElements := []attr.Value{types.StringValue("*")}
					projectsList, _ := types.ListValue(types.StringType, projectElements)
					policy.Projects = projectsList

					policy.Organization = basetypes.NewStringNull()
					emptyReposList, _ := types.ListValue(types.StringType, []attr.Value{})
					policy.Repos = emptyReposList

					modified = true
				}
			} else if policy.Scope.ValueString() == "organization" {
				switch policy.Type.ValueString() {
				case "github":
					// Create types.List for repos
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList

					policy.Group = basetypes.NewStringNull()
					emptyProjectsList, _ := types.ListValue(types.StringType, []attr.Value{})
					policy.Projects = emptyProjectsList

					modified = true
				}
			}
			plan.Policies[index] = policy
		}
	}

	if modified {
		diags = resp.Plan.Set(ctx, plan)
		resp.Diagnostics.Append(diags...)
	}

}

// ImportState implements resource.ResourceWithImportState.
func (r *userResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

type userModel struct {
	ID          types.String      `tfsdk:"id"`
	Email       types.String      `tfsdk:"email"`
	UserName    types.String      `tfsdk:"user_name"`
	EmailSuffix types.String      `tfsdk:"email_suffix"`
	SSOGroup    types.String      `tfsdk:"sso_group"`
	AuthType    types.String      `tfsdk:"auth_type"`
	Policies    []UserPolicyModel `tfsdk:"policies"`
}

// Create creates the resource and sets the initial Terraform state.
func (r *userResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	var plan userModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var policies []stepsecurityapi.UserPolicy
	for _, policy := range plan.Policies {
		// Extract repos from types.List
		var repos []string
		if !policy.Repos.IsNull() && !policy.Repos.IsUnknown() {
			reposValues := make([]string, 0, len(policy.Repos.Elements()))
			for _, repoVal := range policy.Repos.Elements() {
				if repoStr, ok := repoVal.(types.String); ok {
					reposValues = append(reposValues, repoStr.ValueString())
				}
			}
			repos = reposValues
		}

		// Extract projects from types.List
		var projects []string
		if !policy.Projects.IsNull() && !policy.Projects.IsUnknown() {
			projectsValues := make([]string, 0, len(policy.Projects.Elements()))
			for _, projectVal := range policy.Projects.Elements() {
				if projectStr, ok := projectVal.(types.String); ok {
					projectsValues = append(projectsValues, projectStr.ValueString())
				}
			}
			projects = projectsValues
		}

		policies = append(policies, stepsecurityapi.UserPolicy{
			Type:         policy.Type.ValueString(),
			Role:         policy.Role.ValueString(),
			Scope:        policy.Scope.ValueString(),
			Organization: policy.Organization.ValueString(),
			Repos:        repos,
			Server:       policy.Group.ValueString(),
			Projects:     projects,
		})
	}

	tflog.Info(ctx, "user", map[string]any{
		"user_name":    plan.UserName.ValueString(),
		"email":        plan.Email.ValueString(),
		"email_suffix": plan.EmailSuffix.ValueString(),
		"sso_group":    plan.SSOGroup.ValueString(),
		"auth_type":    plan.AuthType.ValueString(),
	})

	userCreated, err := r.client.CreateUser(ctx, stepsecurityapi.CreateUserRequest{
		Email:       plan.Email.ValueString(),
		UserName:    plan.UserName.ValueString(),
		EmailSuffix: plan.EmailSuffix.ValueString(),
		SSOGroup:    plan.SSOGroup.ValueString(),
		AuthType:    plan.AuthType.ValueString(),
		Policies:    policies,
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create StepSecurity User",
			err.Error(),
		)
		return
	}

	// get user info created
	user, err := r.client.GetUser(ctx, userCreated.ID)
	if err != nil || user == nil {
		resp.Diagnostics.AddError(
			"Unable to Get StepSecurity User created",
			err.Error(),
		)
		return
	}

	// populate data to store state
	r.updateUserState(ctx, user, &plan)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

func getStringValue(value string) basetypes.StringValue {
	if value == "" {
		return basetypes.NewStringNull()
	}
	return types.StringValue(value)
}

// Read refreshes the Terraform state with the latest data.
func (r *userResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state userModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get user from StepSecurity
	user, err := r.client.GetUser(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read StepSecurity User",
			err.Error(),
		)
		return
	}

	// overwrite items with refreshed state
	r.updateUserState(ctx, user, &state)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *userResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan userModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state userModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policies []stepsecurityapi.UserPolicy
	for _, policy := range plan.Policies {
		// Extract repos from types.List
		var repos []string
		if !policy.Repos.IsNull() && !policy.Repos.IsUnknown() {
			reposValues := make([]string, 0, len(policy.Repos.Elements()))
			for _, repoVal := range policy.Repos.Elements() {
				if repoStr, ok := repoVal.(types.String); ok {
					reposValues = append(reposValues, repoStr.ValueString())
				}
			}
			repos = reposValues
		}

		// Extract projects from types.List
		var projects []string
		if !policy.Projects.IsNull() && !policy.Projects.IsUnknown() {
			projectsValues := make([]string, 0, len(policy.Projects.Elements()))
			for _, projectVal := range policy.Projects.Elements() {
				if projectStr, ok := projectVal.(types.String); ok {
					projectsValues = append(projectsValues, projectStr.ValueString())
				}
			}
			projects = projectsValues
		}

		policies = append(policies, stepsecurityapi.UserPolicy{
			Type:         policy.Type.ValueString(),
			Role:         policy.Role.ValueString(),
			Scope:        policy.Scope.ValueString(),
			Organization: policy.Organization.ValueString(),
			Repos:        repos,
			Server:       policy.Group.ValueString(),
			Projects:     projects,
		})
	}

	// Update user in StepSecurity
	err := r.client.UpdateUser(ctx, stepsecurityapi.UpdateUserRequest{
		UserID:   state.ID.ValueString(),
		Policies: policies,
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update StepSecurity User",
			err.Error(),
		)
		return
	}

	// get user info created
	user, err := r.client.GetUser(ctx, state.ID.ValueString())
	if err != nil || user == nil {
		resp.Diagnostics.AddError(
			"Unable to Get StepSecurity User created",
			err.Error(),
		)
		return
	}

	// overwrite items with refreshed state
	state.Policies = plan.Policies
	r.updateUserState(ctx, user, &state)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *userResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state userModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete user from StepSecurity
	err := r.client.DeleteUser(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete StepSecurity User",
			err.Error(),
		)
		return
	}
}

func (r *userResource) updateUserState(ctx context.Context, user *stepsecurityapi.User, state *userModel) {
	// populate data to store state
	state.ID = types.StringValue(user.ID)
	state.Email = getStringValue(user.Email)
	state.UserName = getStringValue(user.UserName)
	state.EmailSuffix = getStringValue(user.EmailSuffix)
	state.SSOGroup = getStringValue(user.SSOGroup)
	state.AuthType = getStringValue(user.AuthType)
	if !r.MatchPolicies(ctx, state, user.Policies) {
		tflog.Debug(ctx, "user policies do not match with planned state. updating state", map[string]any{
			"user_id": user.ID,
		})
		state.Policies = make([]UserPolicyModel, len(user.Policies))
		for i := range user.Policies {
			state.Policies[i] = r.getUserPolicyModelFromPolicy(user.Policies[i])
		}
	}

}

func (r *userResource) MatchPolicies(ctx context.Context, state *userModel, apiPolicies []stepsecurityapi.UserPolicy) bool {
	if len(state.Policies) != len(apiPolicies) {
		return false
	}
	for _, policy := range state.Policies {
		found := false
		for _, apiPolicy := range apiPolicies {
			if r.matchPolicy(policy, apiPolicy) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchPolicy checks if a planned policy matches an API policy by comparing core attributes
func (r *userResource) matchPolicy(planned UserPolicyModel, api stepsecurityapi.UserPolicy) bool {

	var repos []attr.Value
	for _, repo := range api.Repos {
		repos = append(repos, types.StringValue(repo))
	}

	var projects []attr.Value
	for _, project := range api.Projects {
		projects = append(projects, types.StringValue(project))
	}

	return planned.Type.ValueString() == api.Type &&
		planned.Role.ValueString() == api.Role &&
		planned.Scope.ValueString() == api.Scope &&
		planned.Organization.ValueString() == api.Organization &&
		planned.Group.ValueString() == api.Server &&
		planned.Repos.Equal(types.ListValueMust(types.StringType, repos)) &&
		planned.Projects.Equal(types.ListValueMust(types.StringType, projects))
}

func (r *userResource) getUserPolicyModelFromPolicy(policy stepsecurityapi.UserPolicy) UserPolicyModel {
	var repos []attr.Value
	for _, repo := range policy.Repos {
		repos = append(repos, types.StringValue(repo))
	}

	var projects []attr.Value
	for _, project := range policy.Projects {
		projects = append(projects, types.StringValue(project))
	}

	return UserPolicyModel{
		Type:         getStringValue(policy.Type),
		Role:         getStringValue(policy.Role),
		Scope:        getStringValue(policy.Scope),
		Organization: getStringValue(policy.Organization),
		Repos:        types.ListValueMust(types.StringType, repos),
		Group:        getStringValue(policy.Server),
		Projects:     types.ListValueMust(types.StringType, projects),
	}
}
