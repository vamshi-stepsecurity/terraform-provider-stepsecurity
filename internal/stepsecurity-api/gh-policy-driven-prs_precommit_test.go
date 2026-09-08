package stepsecurityapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fields inside custom_precommit_config are serialized without omitempty, while the
// enclosing pointer keeps it. That split is the whole contract:
//
//   - a nil pointer means "no custom config configured", and the key is absent
//   - a present object always carries both of its fields, so turning
//     update_existing_configuration back off can actually be expressed
//
// With omitempty on the inner bool, false was indistinguishable from unset and the
// request could never say "stop overwriting the existing file". These tests assert on the
// raw JSON because key-absent versus key-present-but-zero only exists after marshaling.

// capturePrecommitRequest records the body of the first policy-driven-pr config POST and
// returns the decoded control_settings.
func capturePrecommitRequest(t *testing.T, cpc *CustomPrecommitConfig, hooks []string) map[string]any {
	t.Helper()

	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body == nil {
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			body = b
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-key", "test-customer")
	require.NoError(t, err)
	apiClient, ok := client.(*APIClient)
	require.True(t, ok, "expected the concrete APIClient")

	require.NoError(t, apiClient.CreatePolicyDrivenPRPolicy(context.Background(), PolicyDrivenPRPolicy{
		Owner:              "example-org",
		SelectedRepos:      []string{"example-repo"},
		UseRepoLevelConfig: true,
		AutoRemdiationOptions: AutoRemdiationOptions{
			CreatePR:              true,
			CustomPrecommitConfig: cpc,
			UpdatePrecommitFile:   hooks,
		},
	}))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings map[string]any `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	return payload.ControlSettings
}

const testPrecommitYAML = "repos:\n" +
	"  - repo: https://github.com/gitleaks/gitleaks\n" +
	"    rev: v8.18.4\n" +
	"    hooks:\n" +
	"      - id: gitleaks\n"

func TestCreatePolicyDrivenPRPolicy_CustomPrecommitConfigFieldsAlwaysSent(t *testing.T) {
	testCases := []struct {
		name string
		cpc  *CustomPrecommitConfig

		// wantObjectPresent distinguishes "no custom config" from an object whose
		// fields happen to be zero.
		wantObjectPresent bool
		wantConfig        string
		wantUpdateExdting bool
	}{
		{
			// The case omitempty broke: the flag has to be expressible as false, or a
			// user who turns off overwriting has no way to say so.
			name: "flag_false_is_sent_explicitly",
			cpc: &CustomPrecommitConfig{
				Config:                      testPrecommitYAML,
				UpdateExistingConfiguration: false,
			},
			wantObjectPresent: true,
			wantConfig:        testPrecommitYAML,
			wantUpdateExdting: false,
		},
		{
			name: "flag_true_is_sent",
			cpc: &CustomPrecommitConfig{
				Config:                      testPrecommitYAML,
				UpdateExistingConfiguration: true,
			},
			wantObjectPresent: true,
			wantConfig:        testPrecommitYAML,
			wantUpdateExdting: true,
		},
		{
			// An empty config is the documented way to fall back to hook selection.
			// The API keys that off the config string, so it has to arrive.
			name:              "empty_config_is_sent_as_empty_string",
			cpc:               &CustomPrecommitConfig{Config: "", UpdateExistingConfiguration: false},
			wantObjectPresent: true,
			wantConfig:        "",
			wantUpdateExdting: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cs := capturePrecommitRequest(t, tc.cpc, nil)

			raw, present := cs["custom_precommit_config"]
			require.Equal(t, tc.wantObjectPresent, present && raw != nil,
				"custom_precommit_config presence; got %v", cs)
			if !tc.wantObjectPresent {
				return
			}

			obj, ok := raw.(map[string]any)
			require.True(t, ok, "custom_precommit_config was not an object: %v", raw)

			gotConfig, configPresent := obj["config"]
			assert.True(t, configPresent, "config must always be present; got %v", obj)
			assert.Equal(t, tc.wantConfig, gotConfig)

			gotFlag, flagPresent := obj["update_existing_configuration"]
			assert.True(t, flagPresent,
				"update_existing_configuration must always be present so false can be expressed; got %v", obj)
			assert.Equal(t, tc.wantUpdateExdting, gotFlag)
		})
	}
}

// TestCreatePolicyDrivenPRPolicy_CustomPrecommitConfigAbsentWhenNil pins the other half of
// the contract: omitempty stays on the pointer, so "no custom config" is still expressed
// by the key being missing rather than by an object full of zero values. Without this,
// every policy would claim an empty custom config and the API could not tell the two
// pre-commit modes apart.
func TestCreatePolicyDrivenPRPolicy_CustomPrecommitConfigAbsentWhenNil(t *testing.T) {
	cs := capturePrecommitRequest(t, nil, []string{"gitleaks"})

	raw, present := cs["custom_precommit_config"]
	assert.False(t, present && raw != nil,
		"custom_precommit_config must be absent when no custom config is set; got %v", cs)
}
