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

// branch_name is serialized without omitempty so that clearing the configured template
// reaches the API as an explicit empty string rather than a missing key. The API replaces
// the stored template wholesale, so an omitted key would also clear it, but only as a
// side effect of that behavior. These tests assert on the raw JSON because the
// distinction that matters, key-absent versus key-present-but-empty, only exists after
// marshaling.

// capturePRTemplateRequest records the body of the first PR-template POST and returns it
// decoded as a generic map, so key presence can be asserted.
func capturePRTemplateRequest(t *testing.T, template GitHubPRTemplate) map[string]any {
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

	require.NoError(t, apiClient.UpdateGitHubPRTemplate(context.Background(), "example-org", template))
	require.NotNil(t, body, "no request was captured")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	return payload
}

func TestUpdateGitHubPRTemplate_BranchNameAlwaysSent(t *testing.T) {
	testCases := []struct {
		name       string
		branchName string
		want       string
	}{
		{
			// The clearing case. With omitempty this key would vanish and the request
			// would say nothing about the branch template at all.
			name:       "empty_is_sent_as_empty_string",
			branchName: "",
			want:       "",
		},
		{
			name:       "template_is_sent_verbatim",
			branchName: "tf-int-{time}-remediation",
			want:       "tf-int-{time}-remediation",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload := capturePRTemplateRequest(t, GitHubPRTemplate{
				Title:         "[StepSecurity] Apply security best practices",
				Summary:       "Test summary",
				CommitMessage: "[StepSecurity] Apply security best practices",
				BranchName:    tc.branchName,
			})

			got, present := payload["branch_name"]
			assert.True(t, present,
				"branch_name must always be present so clearing the template is explicit; got %v", payload)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestUpdateGitHubPRTemplate_BranchNameMatchesOtherScalars pins branch_name to the same
// serialization rule as the other scalar fields on this struct. They are all cleared the
// same way, so a difference would be a latent inconsistency rather than a choice.
func TestUpdateGitHubPRTemplate_BranchNameMatchesOtherScalars(t *testing.T) {
	payload := capturePRTemplateRequest(t, GitHubPRTemplate{})

	for _, key := range []string{"title", "summary", "commit_message", "branch_name"} {
		_, present := payload[key]
		assert.True(t, present,
			"%s must be present even when empty; got %v", key, payload)
	}
}

// TestDeleteGitHubPRTemplate_ClearsBranchName covers the reset path. Delete posts a
// default template, so branch_name has to travel as an empty string for the stored
// template to actually lose its configured value.
func TestDeleteGitHubPRTemplate_ClearsBranchName(t *testing.T) {
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
	require.True(t, ok)

	require.NoError(t, apiClient.DeleteGitHubPRTemplate(context.Background(), "example-org"))
	require.NotNil(t, body, "no request was captured")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))

	got, present := payload["branch_name"]
	assert.True(t, present, "reset must send branch_name so the stored template is cleared; got %v", payload)
	assert.Equal(t, "", got)
}
