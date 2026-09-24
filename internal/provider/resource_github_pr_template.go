package provider

import (
	"context"
	"fmt"
	"regexp"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubPRTemplateResource{}
	_ resource.ResourceWithConfigure   = &githubPRTemplateResource{}
	_ resource.ResourceWithImportState = &githubPRTemplateResource{}
)

// NewGitHubPRTemplateResource is a helper function to simplify the provider implementation.
func NewGitHubPRTemplateResource() resource.Resource {
	return &githubPRTemplateResource{}
}

// githubPRTemplateResource is the resource implementation.
type githubPRTemplateResource struct {
	client stepsecurityapi.Client
}

// Configure adds the provider configured client to the resource.
func (r *githubPRTemplateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
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

// Metadata returns the resource type name.
func (r *githubPRTemplateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_pr_template"
}

// Schema defines the schema for the resource.
func (r *githubPRTemplateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages PR template for policy-driven PRs in a GitHub organization.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of the PR template. This is same as the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The owner/organization name for the PR template.",
			},
			"title": schema.StringAttribute{
				Required:    true,
				Description: "The title template for policy-driven PRs.",
			},
			"summary": schema.StringAttribute{
				Required:    true,
				Description: "The summary template for policy-driven PRs.",
			},
			"commit_message": schema.StringAttribute{
				Required:    true,
				Description: "The commit message template for policy-driven PRs.",
			},
			"labels": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "List of labels to apply to policy-driven PRs.",
			},
			"branch_name": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\{time\}`),
						"must contain the {time} placeholder, which is replaced with a DDHHMM timestamp so each remediation PR gets a unique branch",
					),
				},
				Description: "Template for the remediation PR branch name, for example \"chore-GHA-{time}-stepsecurity-remediation\". Must contain the {time} placeholder, which is replaced with a DDHHMM timestamp so each PR gets a unique branch. Omit to use the default branch name. Applies to the policy-driven PR flow only.",
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPRTemplateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Set the owner in the state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)

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

type githubPRTemplateModel struct {
	ID            types.String `tfsdk:"id"`
	Owner         types.String `tfsdk:"owner"`
	Title         types.String `tfsdk:"title"`
	Summary       types.String `tfsdk:"summary"`
	CommitMessage types.String `tfsdk:"commit_message"`
	Labels        types.List   `tfsdk:"labels"`
	BranchName    types.String `tfsdk:"branch_name"`
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubPRTemplateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPRTemplateModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert Terraform types to Go types for API
	var labels []string
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		elements := plan.Labels.Elements()
		labels = make([]string, len(elements))
		for i, elem := range elements {
			labels[i] = elem.(types.String).ValueString()
		}
	}

	// Create PR template in StepSecurity
	template := stepsecurityapi.GitHubPRTemplate{
		Title:         plan.Title.ValueString(),
		Summary:       plan.Summary.ValueString(),
		CommitMessage: plan.CommitMessage.ValueString(),
		Labels:        labels,
		BranchName:    plan.BranchName.ValueString(),
	}

	err := r.client.UpdateGitHubPRTemplate(ctx, plan.Owner.ValueString(), template)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create GitHub PR Template",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *githubPRTemplateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPRTemplateModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get PR template from StepSecurity
	template, err := r.client.GetGitHubPRTemplate(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read GitHub PR Template",
			err.Error(),
		)
		return
	}

	// Update state with refreshed data
	state.ID = types.StringValue(state.Owner.ValueString())
	state.Title = types.StringValue(template.Title)
	state.Summary = types.StringValue(template.Summary)
	state.CommitMessage = types.StringValue(template.CommitMessage)

	// branch_name is optional and omitted by the API when unset. Map an absent
	// value to null rather than "", otherwise a config that omits branch_name
	// would show a permanent diff.
	if template.BranchName != "" {
		state.BranchName = types.StringValue(template.BranchName)
	} else {
		state.BranchName = types.StringNull()
	}

	// Convert labels to Terraform list
	if len(template.Labels) > 0 {
		labelElements := make([]types.String, len(template.Labels))
		for i, label := range template.Labels {
			labelElements[i] = types.StringValue(label)
		}
		labelList, diagsLabels := types.ListValueFrom(ctx, types.StringType, labelElements)
		resp.Diagnostics.Append(diagsLabels...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Labels = labelList
	} else {
		state.Labels = types.ListNull(types.StringType)
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPRTemplateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPRTemplateModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert Terraform types to Go types for API
	var labels []string
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		elements := plan.Labels.Elements()
		labels = make([]string, len(elements))
		for i, elem := range elements {
			labels[i] = elem.(types.String).ValueString()
		}
	}

	// Update PR template in StepSecurity
	template := stepsecurityapi.GitHubPRTemplate{
		Title:         plan.Title.ValueString(),
		Summary:       plan.Summary.ValueString(),
		CommitMessage: plan.CommitMessage.ValueString(),
		Labels:        labels,
		BranchName:    plan.BranchName.ValueString(),
	}

	err := r.client.UpdateGitHubPRTemplate(ctx, plan.Owner.ValueString(), template)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update GitHub PR Template",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubPRTemplateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPRTemplateModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete PR template from StepSecurity (resets to default values)
	err := r.client.DeleteGitHubPRTemplate(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete GitHub PR Template",
			err.Error(),
		)
		return
	}
}
