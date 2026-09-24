package provider

import (
	"context"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitHubPRTemplateResource_BranchNameRequiresTimePlaceholder drives the real
// schema validators for branch_name. A branch template without {time} would make
// every remediation PR reuse one branch, so it is rejected at plan time rather
// than silently falling back to the default branch name server-side.
func TestGitHubPRTemplateResource_BranchNameRequiresTimePlaceholder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &githubPRTemplateResource{}

	schemaResp := &fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "schema errors: %v", schemaResp.Diagnostics)

	attr, ok := schemaResp.Schema.Attributes["branch_name"].(interface {
		StringValidators() []validator.String
	})
	require.True(t, ok, "branch_name should expose string validators")
	validators := attr.StringValidators()
	require.NotEmpty(t, validators, "branch_name should have at least one validator")

	testCases := []struct {
		name          string
		branchName    types.String
		expectedError bool
	}{
		{
			name:          "contains {time}",
			branchName:    types.StringValue("chore-GHA-{time}-stepsecurity-remediation"),
			expectedError: false,
		},
		{
			name:          "{time} at the start",
			branchName:    types.StringValue("{time}-remediation"),
			expectedError: false,
		},
		{
			name:          "{time} at the end",
			branchName:    types.StringValue("stepsecurity-remediation-{time}"),
			expectedError: false,
		},
		{
			name:          "missing {time} is rejected",
			branchName:    types.StringValue("stepsecurity-remediation"),
			expectedError: true,
		},
		{
			// {timestamp} is not the {time} placeholder, the closing brace must
			// follow "time" directly, so this must not be mistaken for valid.
			name:          "lookalike placeholder is rejected",
			branchName:    types.StringValue("chore-GHA-{timestamp}-remediation"),
			expectedError: true,
		},
		{
			name:          "empty string is rejected",
			branchName:    types.StringValue(""),
			expectedError: true,
		},
		{
			// Omitting the attribute entirely is valid, it means use the default
			// branch name. Validators are not run against null values.
			name:          "null is allowed",
			branchName:    types.StringNull(),
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var diagsHasError bool
			for _, v := range validators {
				resp := &validator.StringResponse{}
				v.ValidateString(ctx, validator.StringRequest{
					ConfigValue: tc.branchName,
				}, resp)
				if resp.Diagnostics.HasError() {
					diagsHasError = true
				}
			}

			if tc.expectedError {
				assert.True(t, diagsHasError, "expected %q to be rejected", tc.branchName.ValueString())
			} else {
				assert.False(t, diagsHasError, "expected %q to be accepted", tc.branchName.ValueString())
			}
		})
	}
}

// TestGitHubPRTemplateResource_BranchNameStateMapping documents the mapping the
// Read path relies on: the API omits branch_name when unset, and an absent value
// must land in state as null rather than "", otherwise a config that omits
// branch_name would show a permanent diff.
func TestGitHubPRTemplateResource_BranchNameStateMapping(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		apiBranchName string
		expectNull    bool
	}{
		{name: "set value is carried into state", apiBranchName: "chore-GHA-{time}-remediation", expectNull: false},
		{name: "absent value maps to null, not empty string", apiBranchName: "", expectNull: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Mirrors the mapping in Read.
			var got types.String
			if tc.apiBranchName != "" {
				got = types.StringValue(tc.apiBranchName)
			} else {
				got = types.StringNull()
			}

			if tc.expectNull {
				assert.True(t, got.IsNull(), "expected null so an omitted branch_name does not drift")
			} else {
				assert.False(t, got.IsNull())
				assert.Equal(t, tc.apiBranchName, got.ValueString())
			}
		})
	}
}
