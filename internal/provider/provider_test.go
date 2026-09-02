package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"stepsecurity": providerserver.NewProtocol6WithError(New("test")()),
}

func TestStepSecurityProvider(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		provider provider.Provider
	}{
		{
			name:     "default",
			provider: New("test")(),
		},
		{
			name:     "version_dev",
			provider: New("dev")(),
		},
		{
			name:     "version_prod",
			provider: New("1.0.0")(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			// Test Metadata
			metadataReq := provider.MetadataRequest{}
			metadataResp := &provider.MetadataResponse{}
			tc.provider.Metadata(ctx, metadataReq, metadataResp)

			if metadataResp.TypeName != "stepsecurity" {
				t.Errorf("Expected TypeName to be 'stepsecurity', got %s", metadataResp.TypeName)
			}

			// Test Schema
			schemaReq := provider.SchemaRequest{}
			schemaResp := &provider.SchemaResponse{}
			tc.provider.Schema(ctx, schemaReq, schemaResp)

			if schemaResp.Diagnostics.HasError() {
				t.Errorf("Schema() returned unexpected errors: %v", schemaResp.Diagnostics)
			}

			// Verify required attributes exist
			expectedAttrs := []string{"api_base_url", "api_key", "customer"}
			for _, attr := range expectedAttrs {
				if _, exists := schemaResp.Schema.Attributes[attr]; !exists {
					t.Errorf("Expected attribute %s not found in schema", attr)
				}
			}

			// Test DataSources
			dataSources := tc.provider.DataSources(ctx)
			if len(dataSources) == 0 {
				t.Error("Expected at least one data source")
			}

			// Test Resources
			resources := tc.provider.Resources(ctx)
			if len(resources) == 0 {
				t.Error("Expected at least one resource")
			}
		})
	}
}

func TestStepSecurityProvider_DeveloperMDMRegistration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := New("test")()

	resourceNames := map[string]bool{}
	for _, factory := range p.Resources(ctx) {
		resp := &fwresource.MetadataResponse{}
		factory().Metadata(ctx, fwresource.MetadataRequest{ProviderTypeName: "stepsecurity"}, resp)
		resourceNames[resp.TypeName] = true
	}
	for _, name := range []string{
		"stepsecurity_developer_mdm_ide_extension_policy",
		"stepsecurity_developer_mdm_package_config_policy",
		"stepsecurity_developer_mdm_profile",
	} {
		if !resourceNames[name] {
			t.Errorf("expected resource %q to be registered", name)
		}
	}

	dataSourceNames := map[string]bool{}
	for _, factory := range p.DataSources(ctx) {
		resp := &fwdatasource.MetadataResponse{}
		factory().Metadata(ctx, fwdatasource.MetadataRequest{ProviderTypeName: "stepsecurity"}, resp)
		dataSourceNames[resp.TypeName] = true
	}
	for _, name := range []string{
		"stepsecurity_developer_mdm_profile_export",
		"stepsecurity_developer_mdm_device_compliance",
		"stepsecurity_developer_mdm_profile_compliance",
	} {
		if !dataSourceNames[name] {
			t.Errorf("expected data source %q to be registered", name)
		}
	}
}

func TestStepSecurityProvider_Configure(t *testing.T) {

	testCases := []struct {
		name          string
		config        map[string]any
		envVars       map[string]string
		expectedError bool
		errorContains string
	}{
		{
			name: "valid_config_all_attributes",
			config: map[string]any{
				"api_base_url": "http://localhost:1234",
				"api_key":      "step_abcdefg",
				"customer":     "tf-acc-test",
			},
			envVars:       map[string]string{},
			expectedError: false,
		},
		{
			name:   "valid_config_env_vars",
			config: map[string]any{},
			envVars: map[string]string{
				"STEP_SECURITY_API_BASE_URL": "http://localhost:1234",
				"STEP_SECURITY_API_KEY":      "step_abcdefg",
				"STEP_SECURITY_CUSTOMER":     "tf-acc-test",
			},
			expectedError: false,
		},
		{
			name: "config_overrides_env_vars",
			config: map[string]any{
				"api_base_url": "http://localhost:1234",
				"api_key":      "step_abcdefg",
				"customer":     "tf-acc-test",
			},
			envVars: map[string]string{
				"STEP_SECURITY_API_BASE_URL": "https://env.stepsecurity.io",
				"STEP_SECURITY_API_KEY":      "env-key",
				"STEP_SECURITY_CUSTOMER":     "env-customer",
			},
			expectedError: false,
		},
		{
			name: "missing_api_key",
			config: map[string]any{
				"api_base_url": "https://api.stepsecurity.io",
			},
			envVars:       map[string]string{},
			expectedError: true,
			errorContains: "Missing StepSecurity API key",
		},
		{
			name: "missing_customer",
			config: map[string]any{
				"api_base_url": "https://api.stepsecurity.io",
				"api_key":      "test-key",
			},
			envVars:       map[string]string{},
			expectedError: true,
			errorContains: "Missing StepSecurity Customer",
		},
		{
			name: "empty_api_base_url",
			config: map[string]any{
				"api_base_url": "",
				"api_key":      "test-key",
				"customer":     "test-customer",
			},
			envVars:       map[string]string{},
			expectedError: true,
			errorContains: "Attribute api_base_url must be a valid HTTP or HTTPS URL,",
		},
		{
			name: "empty_api_key",
			config: map[string]any{
				"api_base_url": "https://api.stepsecurity.io",
				"api_key":      "",
				"customer":     "test-customer",
			},
			envVars:       map[string]string{},
			expectedError: true,
			errorContains: "Missing StepSecurity API key",
		},
		{
			name: "empty_customer",
			config: map[string]any{
				"api_base_url": "https://api.stepsecurity.io",
				"api_key":      "test-key",
				"customer":     "",
			},
			envVars:       map[string]string{},
			expectedError: true,
			errorContains: "Missing StepSecurity Customer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Set environment variables
			for key, value := range tc.envVars {
				t.Setenv(key, value)
			}

			// Clear environment variables if not set in test case
			if _, exists := tc.envVars["STEP_SECURITY_API_BASE_URL"]; !exists {
				//nolint:errcheck
				os.Unsetenv("STEP_SECURITY_API_BASE_URL")
			}
			if _, exists := tc.envVars["STEP_SECURITY_API_KEY"]; !exists {
				//nolint:errcheck
				os.Unsetenv("STEP_SECURITY_API_KEY")
			}
			if _, exists := tc.envVars["STEP_SECURITY_CUSTOMER"]; !exists {
				//nolint:errcheck
				os.Unsetenv("STEP_SECURITY_CUSTOMER")
			}

			// Create provider configuration
			config := testStepSecurityProviderConfig(tc.config)

			// Test configuration
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: config,
						ExpectError: func() *regexp.Regexp {
							if tc.expectedError {
								return regexp.MustCompile(tc.errorContains)
							}
							return nil
						}(),
					},
				},
			})
		})
	}
}

func testStepSecurityProviderConfig(config map[string]any) string {
	providerConfig := `
provider "stepsecurity" {
`

	for key, value := range config {
		if strValue, ok := value.(string); ok {
			providerConfig += fmt.Sprintf(`  %s = "%s"
`, key, strValue)
		}
	}

	providerConfig += `}
# Minimal resource to test provider configuration
resource "stepsecurity_user" "test" {
  user_name = "test124"
  auth_type = "Github"
  policies = [
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
	]
}
`
	return providerConfig
}
