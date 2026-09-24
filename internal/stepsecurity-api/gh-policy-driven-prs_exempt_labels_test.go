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

// exemptRunnerLabels is serialized without omitempty so that clearing the set reaches
// the API as an explicit empty list rather than a missing key. These tests assert on the
// raw JSON because the distinction that matters, key-absent versus key-present-but-empty,
// only exists after marshaling.

// captureHardenRunnerRequest records the body of the first policy-driven-pr config POST
// and returns the decoded harden_runner_config object. A missing object is reported as a
// nil map so callers can tell it apart from an object with no labels.
func captureHardenRunnerRequest(t *testing.T, hrc *HardenRunnerConfig) (map[string]any, bool) {
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
			CreatePR:           true,
			HardenRunnerConfig: hrc,
		},
	}))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings struct {
			HardenRunnerConfig map[string]any `json:"harden_runner_config"`
		} `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))

	hr := payload.ControlSettings.HardenRunnerConfig
	return hr, hr != nil
}

func TestCreatePolicyDrivenPRPolicy_ExemptRunnerLabelsAlwaysSent(t *testing.T) {
	testCases := []struct {
		name   string
		labels []string
		// want is the decoded JSON value for exemptRunnerLabels. An empty slice means
		// the key must be present and empty, which is what clearing depends on.
		want []any
	}{
		{
			// The clearing case. With omitempty this key would vanish and the request
			// would carry no statement about the exempt set at all.
			name:   "empty_slice_is_sent_as_empty_list",
			labels: []string{},
			want:   []any{},
		},
		{
			// A nil slice is what the provider produces when the attribute is absent.
			// json marshals it to null, which the API reads as "no labels", same as [].
			name:   "nil_slice_is_sent_as_null",
			labels: nil,
			want:   nil,
		},
		{
			name:   "values_are_sent_verbatim",
			labels: []string{"gpu-*", "arm64-?"},
			want:   []any{"gpu-*", "arm64-?"},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hr, present := captureHardenRunnerRequest(t, &HardenRunnerConfig{
				Config:       "- name: Harden the runner\n  uses: step-security/harden-runner@v2\n",
				RunnerLabels: []string{"ubuntu-latest"},

				ExemptRunnerLabels: tc.labels,
			})
			require.True(t, present, "harden_runner_config was not sent at all")

			got, keyPresent := hr["exemptRunnerLabels"]
			assert.True(t, keyPresent,
				"exemptRunnerLabels must always be present so an empty set can clear the stored value; got %v", hr)

			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestCreatePolicyDrivenPRPolicy_ExemptRunnerLabelsMatchesRunnerLabels pins the two label
// fields to the same serialization rule. They are the same shape and are cleared the same
// way, so a difference between them would be a latent inconsistency rather than a choice.
func TestCreatePolicyDrivenPRPolicy_ExemptRunnerLabelsMatchesRunnerLabels(t *testing.T) {
	hr, present := captureHardenRunnerRequest(t, &HardenRunnerConfig{
		Config:             "- name: Harden the runner\n  uses: step-security/harden-runner@v2\n",
		RunnerLabels:       []string{},
		ExemptRunnerLabels: []string{},
	})
	require.True(t, present, "harden_runner_config was not sent at all")

	_, runnerPresent := hr["runnerLabels"]
	_, exemptPresent := hr["exemptRunnerLabels"]
	assert.True(t, runnerPresent, "runnerLabels missing; got %v", hr)
	assert.Equal(t, runnerPresent, exemptPresent,
		"runnerLabels and exemptRunnerLabels must serialize the same way; got %v", hr)
}
