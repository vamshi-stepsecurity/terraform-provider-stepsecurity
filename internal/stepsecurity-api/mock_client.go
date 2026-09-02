package stepsecurityapi

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// Mock client for testing - implements all required methods
type MockStepSecurityClient struct {
	mock.Mock
}

// User methods
func (m *MockStepSecurityClient) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*CreateUserResponse), args.Error(1)
}

func (m *MockStepSecurityClient) GetUser(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStepSecurityClient) ListUsers(ctx context.Context) ([]User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]User), args.Error(1)
}

// GitHub Notification Settings methods
func (m *MockStepSecurityClient) CreateNotificationSettings(ctx context.Context, req GitHubNotificationSettingsRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetNotificationSettings(ctx context.Context, owner string) (*NotificationSettings, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(*NotificationSettings), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateNotificationSettings(ctx context.Context, req GitHubNotificationSettingsRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteNotificationSettings(ctx context.Context, owner string) error {
	args := m.Called(ctx, owner)
	return args.Error(0)
}

// Policy-driven PR methods
func (m *MockStepSecurityClient) CreatePolicyDrivenPRPolicy(ctx context.Context, req PolicyDrivenPRPolicy) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) (*PolicyDrivenPRPolicy, error) {
	args := m.Called(ctx, owner, repos)
	return args.Get(0).(*PolicyDrivenPRPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DiscoverPolicyDrivenPRConfig(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(*PolicyDrivenPRPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) UpdatePolicyDrivenPRPolicy(ctx context.Context, req PolicyDrivenPRPolicy, removedRepos []string) error {
	args := m.Called(ctx, req, removedRepos)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error {
	args := m.Called(ctx, owner, repos)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetSubscriptionStatus(ctx context.Context, owner, repo string) (*SubscriptionStatus, error) {
	args := m.Called(ctx, owner, repo)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SubscriptionStatus), args.Error(1)
}

func (m *MockStepSecurityClient) CreateGitHubPolicyStorePolicy(ctx context.Context, policy *GitHubPolicyStorePolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) (*GitHubPolicyStorePolicy, error) {
	args := m.Called(ctx, owner, policyName)
	return args.Get(0).(*GitHubPolicyStorePolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	args := m.Called(ctx, owner, policyName)
	return args.Error(0)
}

func (m *MockStepSecurityClient) AttachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string, request *GitHubPolicyAttachRequest) error {
	args := m.Called(ctx, owner, policyName, request)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DetachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	args := m.Called(ctx, owner, policyName)
	return args.Error(0)
}

func (m *MockStepSecurityClient) CreateSuppressionRule(ctx context.Context, rule SuppressionRule) (*SuppressionRule, error) {
	args := m.Called(ctx, rule)
	return args.Get(0).(*SuppressionRule), args.Error(1)
}

func (m *MockStepSecurityClient) ReadSuppressionRule(ctx context.Context, ruleID string) (*SuppressionRule, error) {
	args := m.Called(ctx, ruleID)
	return args.Get(0).(*SuppressionRule), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateSuppressionRule(ctx context.Context, rule SuppressionRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteSuppressionRule(ctx context.Context, ruleID string) error {
	args := m.Called(ctx, ruleID)
	return args.Error(0)
}

// GitHub Run Policy methods
func (m *MockStepSecurityClient) ListRunPolicies(ctx context.Context, owner string) ([]RunPolicy, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).([]RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) CreateRunPolicy(ctx context.Context, owner string, policy CreateRunPolicyRequest) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policy)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) GetRunPolicy(ctx context.Context, owner string, policyID string) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policyID)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateRunPolicy(ctx context.Context, owner string, policyID string, policy UpdateRunPolicyRequest) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policyID, policy)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteRunPolicy(ctx context.Context, owner string, policyID string) error {
	args := m.Called(ctx, owner, policyID)
	return args.Error(0)
}

// GitHub PR Checks methods
func (m *MockStepSecurityClient) GetPRChecksConfig(ctx context.Context, owner string) (GitHubPRChecksConfig, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(GitHubPRChecksConfig), args.Error(1)
}

func (m *MockStepSecurityClient) UpdatePRChecksConfig(ctx context.Context, owner string, req GitHubPRChecksConfig) error {
	args := m.Called(ctx, owner, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeletePRChecksConfig(ctx context.Context, owner string) error {
	args := m.Called(ctx, owner)
	return args.Error(0)
}

// GitHub PR Template methods
func (m *MockStepSecurityClient) GetGitHubPRTemplate(ctx context.Context, owner string) (*GitHubPRTemplate, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(*GitHubPRTemplate), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateGitHubPRTemplate(ctx context.Context, owner string, template GitHubPRTemplate) error {
	args := m.Called(ctx, owner, template)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteGitHubPRTemplate(ctx context.Context, owner string) error {
	args := m.Called(ctx, owner)
	return args.Error(0)
}

// Custom Role methods
func (m *MockStepSecurityClient) ListRoles(ctx context.Context) ([]Role, error) {
	args := m.Called(ctx)
	return args.Get(0).([]Role), args.Error(1)
}

func (m *MockStepSecurityClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockStepSecurityClient) GetRole(ctx context.Context, roleID string) (*Role, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateRole(ctx context.Context, roleID string, req UpdateRoleRequest) (*Role, error) {
	args := m.Called(ctx, roleID, req)
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteRole(ctx context.Context, roleID string) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetPermissionCatalog(ctx context.Context) (*FeatureCatalog, error) {
	args := m.Called(ctx)
	return args.Get(0).(*FeatureCatalog), args.Error(1)
}

// Secure Registry Policy methods
func (m *MockStepSecurityClient) GetRegistryControls(ctx context.Context, registry string) (*SecureRegistryControls, error) {
	args := m.Called(ctx, registry)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SecureRegistryControls), args.Error(1)
}

func (m *MockStepSecurityClient) UpsertRegistryControls(ctx context.Context, registry string, req UpsertSecureRegistryControlsRequest) (*SecureRegistryControls, error) {
	args := m.Called(ctx, registry, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SecureRegistryControls), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteRegistryControls(ctx context.Context, registry string) error {
	args := m.Called(ctx, registry)
	return args.Error(0)
}

// Developer MDM Policy methods
func (m *MockStepSecurityClient) CreateDeveloperMDMPolicy(ctx context.Context, req DeveloperMDMPolicyRequest) (*DeveloperMDMPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) ListDeveloperMDMPolicies(ctx context.Context) ([]DeveloperMDMPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]DeveloperMDMPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) GetDeveloperMDMPolicy(ctx context.Context, policyID string) (*DeveloperMDMPolicy, error) {
	args := m.Called(ctx, policyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateDeveloperMDMPolicy(ctx context.Context, policyID string, req DeveloperMDMPolicyRequest) (*DeveloperMDMPolicy, error) {
	args := m.Called(ctx, policyID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteDeveloperMDMPolicy(ctx context.Context, policyID string) error {
	args := m.Called(ctx, policyID)
	return args.Error(0)
}

// Developer MDM Profile methods
func (m *MockStepSecurityClient) CreateDeveloperMDMProfile(ctx context.Context, req DeveloperMDMProfileRequest) (*DeveloperMDMProfile, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMProfile), args.Error(1)
}

func (m *MockStepSecurityClient) ListDeveloperMDMProfiles(ctx context.Context) ([]DeveloperMDMProfile, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]DeveloperMDMProfile), args.Error(1)
}

func (m *MockStepSecurityClient) GetDeveloperMDMProfile(ctx context.Context, profileID string) (*DeveloperMDMProfile, error) {
	args := m.Called(ctx, profileID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMProfile), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateDeveloperMDMProfile(ctx context.Context, profileID string, req DeveloperMDMProfileRequest) (*DeveloperMDMProfile, error) {
	args := m.Called(ctx, profileID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMProfile), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteDeveloperMDMProfile(ctx context.Context, profileID string) error {
	args := m.Called(ctx, profileID)
	return args.Error(0)
}

// Developer MDM Export and Compliance methods
func (m *MockStepSecurityClient) ExportDeveloperMDMProfile(ctx context.Context, profileID, os, category, target, format string) (*DeveloperMDMExportArtifact, error) {
	args := m.Called(ctx, profileID, os, category, target, format)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMExportArtifact), args.Error(1)
}

func (m *MockStepSecurityClient) GetDeveloperMDMDeviceCompliance(ctx context.Context, deviceID string) (*DeveloperMDMDeviceComplianceResponse, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMDeviceComplianceResponse), args.Error(1)
}

func (m *MockStepSecurityClient) GetDeveloperMDMProfileCompliance(ctx context.Context, profileID string) (*DeveloperMDMProfileComplianceResponse, error) {
	args := m.Called(ctx, profileID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeveloperMDMProfileComplianceResponse), args.Error(1)
}
