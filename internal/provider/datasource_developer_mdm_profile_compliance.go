package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &developerMDMProfileComplianceDataSource{}
	_ datasource.DataSourceWithConfigure = &developerMDMProfileComplianceDataSource{}
)

// NewDeveloperMDMProfileComplianceDataSource is a helper function to simplify the provider implementation.
func NewDeveloperMDMProfileComplianceDataSource() datasource.DataSource {
	return &developerMDMProfileComplianceDataSource{}
}

// developerMDMProfileComplianceDataSource is the data source implementation.
type developerMDMProfileComplianceDataSource struct {
	client stepsecurityapi.Client
}

// developerMDMProfileComplianceDataSourceModel maps the data source schema data.
type developerMDMProfileComplianceDataSourceModel struct {
	ProfileID  types.String `tfsdk:"profile_id"`
	Compliance types.List   `tfsdk:"compliance"`
}

// Metadata returns the data source type name.
func (d *developerMDMProfileComplianceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_developer_mdm_profile_compliance"
}

// Schema defines the schema for the data source.
func (d *developerMDMProfileComplianceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads runtime Developer MDM compliance for devices governed by one profile. This is read-only " +
			"observability and must not be used as desired state. Compliance states change outside Terraform and do not drive drift.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Profile identifier to read compliance for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"compliance": developerMDMComplianceSchemaAttribute("Compliance rows reported for devices governed by this profile."),
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *developerMDMProfileComplianceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read fetches profile compliance rows and writes them to state.
func (d *developerMDMProfileComplianceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config developerMDMProfileComplianceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := d.client.GetDeveloperMDMProfileCompliance(ctx, config.ProfileID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Developer MDM profile compliance",
			"Could not read compliance for profile "+config.ProfileID.ValueString()+": "+err.Error(),
		)
		return
	}

	listValue, diags := developerMDMComplianceListValue(response.Compliance)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	config.Compliance = listValue

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
