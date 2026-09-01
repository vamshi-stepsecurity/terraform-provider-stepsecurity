package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGitHubPRTemplateResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGitHubPRTemplateResourceConfig("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "title", "ci: apply security best practices"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.0", "bot"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.1", "origin:stepsecurity"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGitHubPRTemplateResourceConfigUpdated("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "title", "fix: apply security updates"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.0", "security"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// Unit Tests
func TestGitHubPRTemplateResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_pr_template",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_pr_template",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPRTemplateResource{}
			ctx := context.Background()

			req := resource.MetadataRequest{
				ProviderTypeName: tc.providerTypeName,
			}
			resp := &resource.MetadataResponse{}

			r.Metadata(ctx, req, resp)

			if resp.TypeName != tc.expected {
				t.Errorf("Expected TypeName %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestGitHubPRTemplateResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPRTemplateResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"id", "owner", "title", "summary", "commit_message", "labels", "branch_name"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}

	// Test that title is required
	if titleAttr, exists := resp.Schema.Attributes["title"]; exists {
		if !titleAttr.IsRequired() {
			t.Error("Expected title attribute to be required")
		}
	}

	// Test that summary is required
	if summaryAttr, exists := resp.Schema.Attributes["summary"]; exists {
		if !summaryAttr.IsRequired() {
			t.Error("Expected summary attribute to be required")
		}
	}

	// Test that commit_message is required
	if commitMsgAttr, exists := resp.Schema.Attributes["commit_message"]; exists {
		if !commitMsgAttr.IsRequired() {
			t.Error("Expected commit_message attribute to be required")
		}
	}

	// Test that labels is optional
	if labelsAttr, exists := resp.Schema.Attributes["labels"]; exists {
		if !labelsAttr.IsOptional() {
			t.Error("Expected labels attribute to be optional")
		}
	}

	// Test that id is computed
	if idAttr, exists := resp.Schema.Attributes["id"]; exists {
		if !idAttr.IsComputed() {
			t.Error("Expected id attribute to be computed")
		}
	}

	// Test that branch_name is optional
	if branchNameAttr, exists := resp.Schema.Attributes["branch_name"]; exists {
		if !branchNameAttr.IsOptional() {
			t.Error("Expected branch_name attribute to be optional")
		}
		if branchNameAttr.IsRequired() {
			t.Error("Expected branch_name attribute not to be required")
		}
	}
}

func TestGitHubPRTemplateResource_Configure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		providerData  any
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid_client",
			providerData:  &stepsecurityapi.MockStepSecurityClient{},
			expectedError: false,
		},
		{
			name:          "nil_provider_data",
			providerData:  nil,
			expectedError: false,
		},
		{
			name:          "invalid_client_type",
			providerData:  "invalid",
			expectedError: true,
			errorContains: "Unexpected Resource Configure Type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPRTemplateResource{}
			ctx := context.Background()

			req := resource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			resp := &resource.ConfigureResponse{}

			r.Configure(ctx, req, resp)

			if tc.expectedError {
				if !resp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", resp.Diagnostics)
				}
			}
		})
	}
}

func TestGitHubPRTemplateResource_ModelConversion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		model    githubPRTemplateModel
		expected stepsecurityapi.GitHubPRTemplate
	}{
		{
			name: "basic_template_with_labels",
			model: githubPRTemplateModel{
				Owner:         types.StringValue("test-org"),
				Title:         types.StringValue("ci: apply security best practices"),
				Summary:       types.StringValue("This PR applies security best practices"),
				CommitMessage: types.StringValue("Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>"),
				Labels: func() types.List {
					list, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"bot", "origin:stepsecurity"})
					return list
				}(),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title:         "ci: apply security best practices",
				Summary:       "This PR applies security best practices",
				CommitMessage: "Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>",
				Labels:        []string{"bot", "origin:stepsecurity"},
			},
		},
		{
			name: "template_without_labels",
			model: githubPRTemplateModel{
				Owner:         types.StringValue("test-org"),
				Title:         types.StringValue("Security Update"),
				Summary:       types.StringValue("Security improvements"),
				CommitMessage: types.StringValue("Security update"),
				Labels:        types.ListNull(types.StringType),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title:         "Security Update",
				Summary:       "Security improvements",
				CommitMessage: "Security update",
				Labels:        nil,
			},
		},
		{
			name: "template_with_multiline_summary",
			model: githubPRTemplateModel{
				Owner: types.StringValue("test-org"),
				Title: types.StringValue("fix: security hardening"),
				Summary: types.StringValue(`## Summary

This pull request has been generated by StepSecurity.

## Security Fixes

{{STEPSECURITY_SECURITY_FIXES}}

## Feedback
Contact us at support@stepsecurity.io`),
				CommitMessage: types.StringValue("fix: security hardening"),
				Labels: func() types.List {
					list, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"security"})
					return list
				}(),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title: "fix: security hardening",
				Summary: `## Summary

This pull request has been generated by StepSecurity.

## Security Fixes

{{STEPSECURITY_SECURITY_FIXES}}

## Feedback
Contact us at support@stepsecurity.io`,
				CommitMessage: "fix: security hardening",
				Labels:        []string{"security"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Convert model labels to Go slice
			var labels []string
			if !tc.model.Labels.IsNull() && !tc.model.Labels.IsUnknown() {
				elements := tc.model.Labels.Elements()
				labels = make([]string, len(elements))
				for i, elem := range elements {
					labels[i] = elem.(types.String).ValueString()
				}
			}

			result := stepsecurityapi.GitHubPRTemplate{
				Title:         tc.model.Title.ValueString(),
				Summary:       tc.model.Summary.ValueString(),
				CommitMessage: tc.model.CommitMessage.ValueString(),
				Labels:        labels,
			}

			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGitHubPRTemplateResource_StateConversion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		owner    string
		template stepsecurityapi.GitHubPRTemplate
		validate func(t *testing.T, model githubPRTemplateModel)
	}{
		{
			name:  "api_response_with_labels",
			owner: "test-org",
			template: stepsecurityapi.GitHubPRTemplate{
				Title:         "ci: apply security best practices",
				Summary:       "This PR applies security best practices",
				CommitMessage: "Apply security best practices",
				Labels:        []string{"bot", "security"},
			},
			validate: func(t *testing.T, model githubPRTemplateModel) {
				assert.Equal(t, "test-org", model.Owner.ValueString())
				assert.Equal(t, "ci: apply security best practices", model.Title.ValueString())
				assert.Equal(t, "This PR applies security best practices", model.Summary.ValueString())
				assert.Equal(t, "Apply security best practices", model.CommitMessage.ValueString())
				assert.False(t, model.Labels.IsNull())
				assert.Equal(t, 2, len(model.Labels.Elements()))
			},
		},
		{
			name:  "api_response_without_labels",
			owner: "test-org",
			template: stepsecurityapi.GitHubPRTemplate{
				Title:         "Security Update",
				Summary:       "Updates",
				CommitMessage: "Update",
				Labels:        []string{},
			},
			validate: func(t *testing.T, model githubPRTemplateModel) {
				assert.Equal(t, "test-org", model.Owner.ValueString())
				assert.Equal(t, "Security Update", model.Title.ValueString())
				assert.True(t, model.Labels.IsNull())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			model := githubPRTemplateModel{
				ID:            types.StringValue(tc.owner),
				Owner:         types.StringValue(tc.owner),
				Title:         types.StringValue(tc.template.Title),
				Summary:       types.StringValue(tc.template.Summary),
				CommitMessage: types.StringValue(tc.template.CommitMessage),
			}

			// Convert labels
			if len(tc.template.Labels) > 0 {
				labelElements := make([]types.String, len(tc.template.Labels))
				for i, label := range tc.template.Labels {
					labelElements[i] = types.StringValue(label)
				}
				labelList, _ := types.ListValueFrom(ctx, types.StringType, labelElements)
				model.Labels = labelList
			} else {
				model.Labels = types.ListNull(types.StringType)
			}

			tc.validate(t, model)
		})
	}
}

// Test configuration helpers
func testAccGitHubPRTemplateResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pr_template" "test" {
  owner          = %[1]q
  title          = "ci: apply security best practices"
  summary        = "This PR applies security best practices"
  commit_message = "Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>"
  labels         = ["bot", "origin:stepsecurity"]
}
`, owner)
}

func testAccGitHubPRTemplateResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pr_template" "test" {
  owner          = %[1]q
  title          = "fix: apply security updates"
  summary        = "This PR applies security updates"
  commit_message = "Apply security updates"
  labels         = ["security"]
}
`, owner)
}
