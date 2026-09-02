package provider

import (
	"context"
	"os"
	"regexp"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider              = &StepSecurityProvider{}
	_ provider.ProviderWithFunctions = &StepSecurityProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &StepSecurityProvider{
			version: version,
		}
	}
}

// StepSecurityProvider is the provider implementation.
type StepSecurityProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// Metadata returns the provider type name.
func (p *StepSecurityProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "stepsecurity"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *StepSecurityProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"api_base_url": schema.StringAttribute{
				Optional:    true,
				Description: "The base URL of the StepSecurity API. Can be set using the STEP_SECURITY_API_BASE_URL environment variable.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^https?://`),
						"must be a valid HTTP or HTTPS URL",
					),
				},
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Description: "The API key of the StepSecurity API. Can be set using the STEP_SECURITY_API_KEY environment variable. If not provided and STEP_SECURITY_API_KEY is not set, the provider will return an error.",
				Sensitive:   true,
			},
			"customer": schema.StringAttribute{
				Optional:    true,
				Description: "The customer name of the StepSecurity API. Can be set using the STEP_SECURITY_CUSTOMER environment variable. If not provided and STEP_SECURITY_CUSTOMER is not set, the provider will return an error.",
			},
		},
	}
}

// stepSecurityProviderModel maps provider schema data to a Go type.
type stepSecurityProviderModel struct {
	APIBaseURL types.String `tfsdk:"api_base_url"`
	APIKey     types.String `tfsdk:"api_key"`
	Customer   types.String `tfsdk:"customer"`
}

func (p *StepSecurityProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {

	tflog.Info(ctx, "Configuring StepSecurity client")

	// Retrieve provider data from configuration
	var config stepSecurityProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.
	apiBaseURL := os.Getenv("STEP_SECURITY_API_BASE_URL")
	apiKey := os.Getenv("STEP_SECURITY_API_KEY")
	customer := os.Getenv("STEP_SECURITY_CUSTOMER")

	if !config.APIBaseURL.IsNull() {
		apiBaseURL = config.APIBaseURL.ValueString()
	}

	if !config.APIKey.IsNull() {
		apiKey = config.APIKey.ValueString()
	}

	if !config.Customer.IsNull() {
		customer = config.Customer.ValueString()
	}

	if apiBaseURL == "" {
		tflog.Info(ctx, "Using default StepSecurity API base URL")
		apiBaseURL = "https://agent.api.stepsecurity.io"
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_key"),
			"Missing StepSecurity API key",
			"The provider cannot create the StepSecurity API client as there is a missing or empty value for the StepSecurity API key. "+
				"Set the username value in the configuration or use the STEP_SECURITY_API_KEY environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if customer == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("customer"),
			"Missing StepSecurity Customer",
			"The provider cannot create the StepSecurity API client as there is a missing or empty value for the StepSecurity Customer. "+
				"Set the customer value in the configuration or use the STEP_SECURITY_CUSTOMER environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "stepsecurity_api_base_url", apiBaseURL)
	ctx = tflog.SetField(ctx, "stepsecurity_api_key", apiKey)
	ctx = tflog.SetField(ctx, "stepsecurity_customer", customer)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "stepsecurity_api_key")

	tflog.Debug(ctx, "Creating StepSecurity client")

	// Create a new StepSecurity client using the configuration values
	client, err := stepsecurityapi.NewClient(apiBaseURL, apiKey, customer)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create StepSecurity API Client",
			"An unexpected error occurred when creating the StepSecurity API client. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"StepSecurity API Client Error: "+err.Error(),
		)
		return
	}

	// Make the StepSecurity client available during DataSource and Resource
	// type Configure methods.
	resp.DataSourceData = client
	resp.ResourceData = client

	tflog.Info(ctx, "Configured StepSecurity client", map[string]any{"success": true})
}

// DataSources defines the data sources implemented in the provider.
func (p *StepSecurityProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewUsersDataSource,
		NewGithubRunPoliciesDataSource,
		NewDeveloperMDMProfileExportDataSource,
		NewDeveloperMDMDeviceComplianceDataSource,
		NewDeveloperMDMProfileComplianceDataSource,
	}
}

// Resources defines the resources implemented in the provider.
func (p *StepSecurityProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewUserResource,
		NewRoleResource,
		NewGithubRepoNotificationSettingsResource,
		NewPolicyDrivenPRResource,
		NewGithubPolicyStoreResource,
		NewGithubPolicyStoreAttachmentResource,
		NewGithubSupressionRuleResource,
		NewGithubRunPolicyResource,
		NewGitHubChecksResource,
		NewGitHubPRTemplateResource,
		NewSecureRegistryPolicyResource,
		NewDeveloperMDMIDEExtensionPolicyResource,
		NewDeveloperMDMPackageConfigPolicyResource,
		NewDeveloperMDMProfileResource,
	}
}

func (p *StepSecurityProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}
