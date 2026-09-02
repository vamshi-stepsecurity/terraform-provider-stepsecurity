package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &developerMDMProfileExportDataSource{}
	_ datasource.DataSourceWithConfigure = &developerMDMProfileExportDataSource{}
)

// NewDeveloperMDMProfileExportDataSource is a helper function to simplify the provider implementation.
func NewDeveloperMDMProfileExportDataSource() datasource.DataSource {
	return &developerMDMProfileExportDataSource{}
}

// developerMDMProfileExportDataSource is the data source implementation.
type developerMDMProfileExportDataSource struct {
	client stepsecurityapi.Client
}

// developerMDMProfileExportDataSourceModel maps the data source schema data.
type developerMDMProfileExportDataSourceModel struct {
	ProfileID        types.String `tfsdk:"profile_id"`
	OS               types.String `tfsdk:"os"`
	OSDisplayName    types.String `tfsdk:"os_display_name"`
	Category         types.String `tfsdk:"category"`
	Target           types.String `tfsdk:"target"`
	Format           types.String `tfsdk:"format"`
	Filename         types.String `tfsdk:"filename"`
	ContentType      types.String `tfsdk:"content_type"`
	Content          types.String `tfsdk:"content"`
	Hash             types.String `tfsdk:"hash"`
	PreferenceDomain types.String `tfsdk:"preference_domain"`
	Notes            types.String `tfsdk:"notes"`
}

// Metadata returns the data source type name.
func (d *developerMDMProfileExportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_developer_mdm_profile_export"
}

// Schema defines the schema for the data source.
func (d *developerMDMProfileExportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns a compiled Developer MDM import artifact for a profile, category, target, and OS. " +
			"This is read-only and has no Terraform lifecycle. The `content` attribute is the decoded artifact body and " +
			"can be passed directly to `hashicorp/local` `local_file.content` without `jsondecode` or string manipulation. " +
			"This provider does not write files; use the `local` provider for that. On Terraform Cloud or CI, `local_file` " +
			"writes to the remote runner filesystem, not the operator's machine. When the exported policy sets " +
			"`gallery_service_url`, the artifact also carries VS Code's `ExtensionGalleryServiceUrl`, which is how a " +
			"private marketplace is delivered through a customer-owned MDM.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Backend profile UUID to export.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"os": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Target operating system. One of `windows`, `macos`, `linux`.",
				Validators: []validator.String{
					stringvalidator.OneOf("windows", "macos", "linux"),
				},
			},
			"category": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Policy category to export. Defaults to `ide_extension`.",
				Validators: []validator.String{
					stringvalidator.OneOf(stepsecurityapi.DeveloperMDMCategoryIDEExtension),
				},
			},
			"target": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Policy target to export. Defaults to `vscode`.",
				Validators: []validator.String{
					stringvalidator.OneOf(stepsecurityapi.DeveloperMDMTargetVSCode),
				},
			},
			"format": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Selects between the two macOS artifact shapes, and has no effect " +
					"on other platforms. `mobileconfig` (default) is a full configuration profile; " +
					"`plist` is the bare macOS preferences file for MDMs that take a preference domain " +
					"plus a plist. `plist` is only valid with `os = \"macos\"`. Windows and Linux each " +
					"have a single shape — a PowerShell script and a `policy.json` respectively — so for " +
					"those this attribute reports back the selector that was requested and does not " +
					"describe the artifact you received; read `filename` and `content_type` for that.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						stepsecurityapi.DeveloperMDMExportFormatMobileconfig,
						stepsecurityapi.DeveloperMDMExportFormatPlist,
					),
				},
			},
			"os_display_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Human-readable OS label, e.g. `macOS`.",
			},
			"filename": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Suggested artifact filename.",
			},
			"content_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Artifact MIME type.",
			},
			"content": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Decoded artifact body. Pass directly to `local_file.content`. " +
					"For Linux, the inner `AllowedExtensions` value is intentionally a stringified JSON value because " +
					"VS Code's Linux policy loader expects that shape; do not deserialize it. " +
					"For Windows the artifact is a PowerShell script, not a registry file, and `notes` carries the " +
					"exact Intune platform-script settings verbatim.",
			},
			"hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Backend compiled policy hash.",
			},
			"preference_domain": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "macOS managed-preferences domain for this artifact, e.g. " +
					"`com.microsoft.VSCode`. Jamf and Intune require it alongside a `plist` artifact. " +
					"Empty for Windows and Linux.",
			},
			"notes": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Backend deployment notes.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *developerMDMProfileExportDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read fetches the compiled MDM artifact and writes it to state.
func (d *developerMDMProfileExportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config developerMDMProfileExportDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	category := config.Category.ValueString()
	if config.Category.IsNull() || config.Category.IsUnknown() || category == "" {
		category = stepsecurityapi.DeveloperMDMCategoryIDEExtension
	}
	target := config.Target.ValueString()
	if config.Target.IsNull() || config.Target.IsUnknown() || target == "" {
		target = stepsecurityapi.DeveloperMDMTargetVSCode
	}

	format := config.Format.ValueString()
	if config.Format.IsNull() || config.Format.IsUnknown() || format == "" {
		format = stepsecurityapi.DeveloperMDMExportFormatMobileconfig
	}
	if format == stepsecurityapi.DeveloperMDMExportFormatPlist &&
		config.OS.ValueString() != "macos" {
		resp.Diagnostics.AddAttributeError(
			path.Root("format"),
			"plist format requires macOS",
			"The `plist` format is only available for `os = \"macos\"`. Use `mobileconfig` for "+
				"Windows and Linux.",
		)
		return
	}

	artifact, err := d.client.ExportDeveloperMDMProfile(ctx, config.ProfileID.ValueString(), config.OS.ValueString(), category, target, format)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error exporting Developer MDM profile",
			"Could not export profile "+config.ProfileID.ValueString()+": "+err.Error(),
		)
		return
	}

	config.Category = types.StringValue(category)
	if artifact.Target != "" {
		target = artifact.Target
	}
	config.Target = types.StringValue(target)
	// The backend only sets Format inside its macOS branch, so Windows and Linux fall back
	// to the requested selector. Returning null there would drop a value the configuration
	// legally set, which Terraform rejects.
	if artifact.Format != "" {
		format = artifact.Format
	}
	config.Format = types.StringValue(format)
	config.OSDisplayName = types.StringValue(artifact.OSDisplayName)
	config.Filename = types.StringValue(artifact.Filename)
	config.ContentType = types.StringValue(artifact.ContentType)
	config.Content = types.StringValue(artifact.Content)
	config.Hash = types.StringValue(artifact.Hash)
	config.PreferenceDomain = types.StringValue(artifact.PreferenceDomain)
	config.Notes = types.StringValue(artifact.Notes)

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
