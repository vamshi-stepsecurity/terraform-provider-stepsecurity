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

// actions_to_replace is serialized without omitempty so an empty map can clear the
// stored value. The API rejects a request that carries both actions_to_replace and
// replace_all_actions, and its check is for presence rather than content, so an empty
// map built alongside a replace-all request is enough to trip it. These tests pin which
// of the two fields reaches the wire for each configuration.
//
// The assertions are on the raw JSON rather than the Go struct: the distinction that
// matters is key-absent versus key-present-but-empty, and that is only visible after
// marshaling.

// captureConfigRequest stands up a server that records the body of the first
// policy-driven-pr config POST and returns the decoded control_settings.
func captureConfigRequest(t *testing.T, policy PolicyDrivenPRPolicy) map[string]any {
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

	require.NoError(t, apiClient.CreatePolicyDrivenPRPolicy(context.Background(), policy))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings map[string]any `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	return payload.ControlSettings
}

func TestCreatePolicyDrivenPRPolicy_ReplaceAllOmitsEmptyActionsToReplace(t *testing.T) {
	testCases := []struct {
		name string
		// actions is actions_to_replace_with_step_security_actions as configured.
		actions []string
		// exemptedFromReplacement forces replace_all_actions on regardless of actions.
		exemptedFromReplacement []string

		wantActionsToReplacePresent bool
		wantActionsToReplace        map[string]any
		wantReplaceAllActions       any
	}{
		{
			// The wildcard becomes replace_all_actions. Sending an empty map alongside
			// it is what the API rejects, so the key has to be absent.
			name:                        "wildcard_sends_flag_only",
			actions:                     []string{"*"},
			wantActionsToReplacePresent: false,
			wantReplaceAllActions:       true,
		},
		{
			// exempted_from_replacement forces the flag on even though no wildcard was
			// configured, so the empty map has to be dropped here too.
			name:                        "exemptions_only_sends_flag_only",
			actions:                     nil,
			exemptedFromReplacement:     []string{"actions/checkout"},
			wantActionsToReplacePresent: false,
			wantReplaceAllActions:       true,
		},
		{
			// No flag is set, so the empty map must survive: this is the clearing case
			// that dropping omitempty exists to support.
			name:                        "empty_list_sends_empty_map_to_clear",
			actions:                     []string{},
			wantActionsToReplacePresent: true,
			wantActionsToReplace:        map[string]any{},
			wantReplaceAllActions:       nil,
		},
		{
			name:                        "explicit_actions_send_map",
			actions:                     []string{"example-org/example-action"},
			wantActionsToReplacePresent: true,
			wantActionsToReplace:        map[string]any{"example-org/example-action": ""},
			wantReplaceAllActions:       nil,
		},
		{
			// A non-empty map alongside the flag is a real conflict. It is left intact so
			// the API reports it, rather than silently discarding the configured actions.
			name:                        "explicit_actions_with_exemptions_keeps_map",
			actions:                     []string{"example-org/example-action"},
			exemptedFromReplacement:     []string{"actions/checkout"},
			wantActionsToReplacePresent: true,
			wantActionsToReplace:        map[string]any{"example-org/example-action": ""},
			wantReplaceAllActions:       true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cs := captureConfigRequest(t, PolicyDrivenPRPolicy{
				Owner:              "example-org",
				SelectedRepos:      []string{"example-repo"},
				UseRepoLevelConfig: true,
				AutoRemdiationOptions: AutoRemdiationOptions{
					CreatePR:                                true,
					ActionsToReplaceWithStepSecurityActions: tc.actions,
					ExemptedFromReplacement:                 tc.exemptedFromReplacement,
				},
			})

			got, present := cs["actions_to_replace"]
			assert.Equal(t, tc.wantActionsToReplacePresent, present && got != nil,
				"actions_to_replace presence; full control_settings: %v", cs)

			if tc.wantActionsToReplacePresent {
				assert.Equal(t, tc.wantActionsToReplace, got)
			}

			assert.Equal(t, tc.wantReplaceAllActions, cs["replace_all_actions"])
		})
	}
}
