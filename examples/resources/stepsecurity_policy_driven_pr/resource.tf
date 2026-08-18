terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "xxxxxxxx" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "abcdefg"  # can also be set as env variable STEP_SECURITY_CUSTOMER
}

# ============================================================================
# Scenario 1: Org-level config for all repos
# ============================================================================
# Creates policy that applies to ALL repositories in the organization
resource "stepsecurity_policy_driven_pr" "org_level_all" {
  owner          = "test-organization"
  selected_repos = ["*"] # Wildcard applies to all repos
  auto_remediation_options = {
    create_pr                             = true
    create_issue                          = false
    create_github_advanced_security_alert = false
    harden_github_hosted_runner           = true
    pin_actions_to_sha                    = true
    restrict_github_token_permissions     = false
    secure_docker_file                    = false
    actions_to_exempt_while_pinning       = ["actions/checkout", "actions/setup-node"]
    images_to_exempt_while_pinning        = ["amazon*"]
  }
}

# ============================================================================
# Scenario 2: Repo-level config for specific repos
# ============================================================================
# Applies configuration to specific repositories
# Config is applied at repo level
resource "stepsecurity_policy_driven_pr" "repo_level_config" {
  owner          = "test-organization"
  selected_repos = ["test-repo-1", "test-repo-2"]
  auto_remediation_options = {
    create_pr                             = true
    create_issue                          = false
    create_github_advanced_security_alert = false
    harden_github_hosted_runner           = true
    pin_actions_to_sha                    = true
    restrict_github_token_permissions     = true
    secure_docker_file                    = true
    labels_to_replace = {
      "ubuntu-latest-8-cores" = "ubuntu-latest"
      "windows-latest-large"  = "windows-latest"
    }
    actions_to_exempt_while_pinning               = ["actions/checkout", "actions/setup-node"]
    actions_to_replace_with_step_security_actions = ["enricomi/publish-unit-test-result-action", "tj-actions/changed-files"]
    custom_actions_to_replace = {
      "third-party-actions/dynamodb-actions" = "step-security/dynamodb-actions"
    }                                                                // replaces all third-party actions with step-security/dynamodb-actions
    replace_action_on_major_tag_match = true                         # actions in actions_to_replace_with_step_security_actions are replaced only when the major tag matches
    actions_exempted_from_replacement = ["fkirc/skip-*", "amannn/*"] // either actions_to_replace_with_step_security_actions or actions_exempted_from_replacement can be set at a time unless its *
    images_to_exempt_while_pinning    = ["amazon*"]

    # v2-only features (requires policy-driven PR v2 to be enabled)
    update_precommit_file = ["eslint"]
    package_ecosystem = [
      {
        package       = "npm"
        interval      = "daily"
        cooldown_yaml = "default-days: 7\npackage-rules:\n  - match-package-patterns:\n      - \"*\"\n    days: 3\n"
        groups_yaml   = "production-dependencies:\n  patterns:\n    - \"*\"\n  exclude-patterns:\n    - \"@types/*\"\n"
      },
      {
        package  = "pip"
        interval = "weekly"
      }
    ]
    add_workflows = "https://github.com/[owner]/[repo]"
    action_commit_map = {
      "codecov/codecov-action@v5" : "cf3f51a67d2820f7a7cefa0831889fbbef41ca57",
      "codecov/codecov-action@v4" : "5ecb98a3c6b747ed38dc09f787459979aebb39be",
      "google-github-actions/auth@v2" : "ba79af03959ebeac9769e648f473a284504d9193",
      "google-github-actions/auth@v3" : "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093"
    },
    update_existing_configuration = true # update existing dependabot configurations
    harden_runner_config = {
      update_existing_configuration = false
      config                        = "- name: Harden the runner (Audit all outbound calls)\n  uses: step-security/custom-agent@v2\n  with:\n    egress-policy: audit\n    allowed-endpoints: >\n      github.com:443\n"
      target_runner_labels          = ["ubuntu-latest", "macos-latest"]
      exempt_runner_labels          = ["gpu-*", "self-hosted"]
    }
  }
}

# ============================================================================
# Scenario 3: Org-level config with exclusions (opt-out specific repos)
# ============================================================================
# Applies org-level config to all repos EXCEPT the ones in excluded_repos
# Excluded repos will not have any policy-driven PR config applied
resource "stepsecurity_policy_driven_pr" "org_level_with_exclusions" {
  owner          = "test-organization"
  selected_repos = ["*"]
  excluded_repos = ["archived-repo", "test-repo-old"] # These repos opt-out
  auto_remediation_options = {
    create_pr                             = true
    create_issue                          = false
    create_github_advanced_security_alert = false
    harden_github_hosted_runner           = true
    pin_actions_to_sha                    = true
    restrict_github_token_permissions     = false
    secure_docker_file                    = false
  }
}

# ============================================================================
# Scenario 4: Org-level config with filter
# ============================================================================
# Applies org-level config to all repos that match the filter
resource "stepsecurity_policy_driven_pr" "org_level_with_exclusions" {
  owner          = "test-organization"
  selected_repos = ["*"]
  selected_repos_filter = {
    include_repos_only_with_topics = ["topic1", "topic2"]
  }
  auto_remediation_options = {
    create_pr                                     = true
    create_issue                                  = false
    create_github_advanced_security_alert         = false
    harden_github_hosted_runner                   = true
    pin_actions_to_sha                            = true
    restrict_github_token_permissions             = false
    secure_docker_file                            = false
    actions_to_replace_with_step_security_actions = ["*"]                        // all actions with stepsecurity actions will be replaced
    actions_exempted_from_replacement             = ["fkirc/skip-*", "amannn/*"] // all actions except these will be replaced since its specified
  }
}


# ============================================================================
# For importing existing policy driven pr config to terraform state
# ============================================================================
# This will be helpful to manage existing policy driven pr config using terraform
# Alternative to this is to use terraform import command
import {
  to = stepsecurity_policy_driven_pr.org_level_all
  id = "test-organization"
}
