package provider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// TestConvertToStateRepoListsAreDeterministic pins that repos/omit_repos come out of
// convertToState in a stable, sorted order for a fixed API response.
//
// The API returns "repos" as a JSON object, which unmarshals into a Go map, and Go
// randomizes map iteration order on every range. Before this was pinned, two reads of a
// byte-identical response (the plan phase and the apply phase of a single terraform run)
// produced different orderings, and Terraform rendered a reordering diff for a
// configuration that had not changed. A customer hit exactly that.
//
// Ordering churn is normally masked by updateStateListsWithOrderFromPlan, which restores
// the practitioner's configured order when the live list and the planned list hold the
// same elements. That masking drops away the moment the contents genuinely differ (for
// example when the backend reports a repo the practitioner never configured), which is
// when the raw map order leaks into the diff. So this must hold at the convertToState
// layer, not only at the plan-reconciliation layer.
func TestConvertToStateRepoListsAreDeterministic(t *testing.T) {
	r := &githubChecksResource{}
	enabled := true

	// All three global "for all new repos" flags on, so every repo carrying a false
	// per-repo flag is derived into the corresponding omit list.
	cfg := stepsecurityapi.GitHubPRChecksConfig{
		ChecksConfig: stepsecurityapi.ChecksConfig{
			Checks: map[string]stepsecurityapi.CheckConfig{
				"pwn_request_check":      {Enabled: true, Type: "required"},
				"script_injection_check": {Enabled: true, Type: "optional"},
			},
			EnableBaselineCheckForAllNewRepos:  &enabled,
			EnableRequiredChecksForAllNewRepos: &enabled,
			EnableOptionalChecksForAllNewRepos: &enabled,
		},
		Repos: map[string]stepsecurityapi.CheckOptions{
			"server":                       {},
			"client":                       {},
			"notifications-webpush":        {},
			"vibelab-miro-canvas-flows-sk": {},
			"api-gateway":                  {},
		},
	}

	want := []string{
		"api-gateway",
		"client",
		"notifications-webpush",
		"server",
		"vibelab-miro-canvas-flows-sk",
	}

	// A single call cannot distinguish "sorted" from "randomized but lucky", so read
	// repeatedly: an unsorted map range reliably yields several distinct orders here.
	for i := 0; i < 50; i++ {
		state := r.convertToState(context.Background(), "miroapp-dev", cfg)

		required, diags := decodeChecksConfig(context.Background(), state.RequiredChecks)
		require.False(t, diags.HasError())
		require.NotNil(t, required)
		assert.Equal(t, want, r.listToStringSlice(required.OmitRepos), "required_checks.omit_repos order (iteration %d)", i)

		optional, diags := decodeChecksConfig(context.Background(), state.OptionalChecks)
		require.False(t, diags.HasError())
		require.NotNil(t, optional)
		assert.Equal(t, want, r.listToStringSlice(optional.OmitRepos), "optional_checks.omit_repos order (iteration %d)", i)

		baseline, diags := decodeChecksConfig(context.Background(), state.BaselineCheck)
		require.False(t, diags.HasError())
		require.NotNil(t, baseline)
		assert.Equal(t, want, r.listToStringSlice(baseline.OmitRepos), "baseline_check.omit_repos order (iteration %d)", i)
	}
}

// TestConvertToStateReposListIsDeterministic is the mirror of the above for the non-omit
// "repos" lists, which are built from the same map range and so had the same defect.
func TestConvertToStateReposListIsDeterministic(t *testing.T) {
	r := &githubChecksResource{}

	// All global flags off, so repos carrying a true per-repo flag land in "repos".
	cfg := stepsecurityapi.GitHubPRChecksConfig{
		ChecksConfig: stepsecurityapi.ChecksConfig{
			Checks: map[string]stepsecurityapi.CheckConfig{
				"pwn_request_check":      {Enabled: true, Type: "required"},
				"script_injection_check": {Enabled: true, Type: "optional"},
			},
		},
		Repos: map[string]stepsecurityapi.CheckOptions{
			"server":      {Baseline: true, RunRequiredChecks: true, RunOptionalChecks: true},
			"client":      {Baseline: true, RunRequiredChecks: true, RunOptionalChecks: true},
			"api-gateway": {Baseline: true, RunRequiredChecks: true, RunOptionalChecks: true},
			"webhooks":    {Baseline: true, RunRequiredChecks: true, RunOptionalChecks: true},
		},
	}

	want := []string{"api-gateway", "client", "server", "webhooks"}

	for i := 0; i < 50; i++ {
		state := r.convertToState(context.Background(), "miroapp-dev", cfg)

		required, diags := decodeChecksConfig(context.Background(), state.RequiredChecks)
		require.False(t, diags.HasError())
		require.NotNil(t, required)
		assert.Equal(t, want, r.listToStringSlice(required.Repos), "required_checks.repos order (iteration %d)", i)

		optional, diags := decodeChecksConfig(context.Background(), state.OptionalChecks)
		require.False(t, diags.HasError())
		require.NotNil(t, optional)
		assert.Equal(t, want, r.listToStringSlice(optional.Repos), "optional_checks.repos order (iteration %d)", i)

		baseline, diags := decodeChecksConfig(context.Background(), state.BaselineCheck)
		require.False(t, diags.HasError())
		require.NotNil(t, baseline)
		assert.Equal(t, want, r.listToStringSlice(baseline.Repos), "baseline_check.repos order (iteration %d)", i)
	}
}
