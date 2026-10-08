
terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "xxxxxxxx" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "abcdefg"  # can also be set as env variable STEP_SECURITY_API_KEY
}

# creates a githubuser in stepsecurity console to have read access to the organization.
resource "stepsecurity_user" "github_user" {
  user_name = "test-user-1"
  auth_type = "Github"
  policies = [
    {
      type         = "github"
      role         = "auditor"
      scope        = "organization"
      organization = "test-organization"
    }
  ]
}

# creates sso user in stepsecurity console to have tenant admin access to all organizations under the tenant.
resource "stepsecurity_user" "sso_user" {
  email     = "test-user-2@test.com"
  auth_type = "SSO"
  policies = [
    {
      type  = "github"
      role  = "admin"
      scope = "customer"
    }
  ]
}

# creates user that provides read access to the organization for all users with email suffix 'test.com'.
resource "stepsecurity_user" "email_suffix_user" {
  email_suffix = "test.com"
  auth_type    = "SSO"
  policies = [
    {
      type         = "github"
      role         = "auditor"
      scope        = "organization"
      organization = "test-organization"
    }
  ]
}

# creates a custom role and assigns it to a user. The policy role is the custom role's name.
resource "stepsecurity_role" "engineer" {
  name = "engineer"
  permissions = [
    { resource = "workflow-runs", action = "read" },
  ]
}

resource "stepsecurity_user" "custom_role_user" {
  user_name = "test-user"
  auth_type = "Github"
  policies = [
    {
      type         = "github"
      role         = stepsecurity_role.engineer.name
      scope        = "organization"
      organization = "test-organization"
    }
  ]
}

# For importing existing user to terraform state
# this will be helpful to manage existing user using terraform
# alternative to this is to use terraform import command
import {
  to = stepsecurity_user.github_user
  id = ACTUAL_USER_ID
}