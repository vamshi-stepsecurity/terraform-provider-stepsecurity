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

# Points managed devices' npm config (~/.npmrc) at the tenant's StepSecurity secure registry.
# The registry URL and the tenant's registry auth key are injected by StepSecurity at compile time.
resource "stepsecurity_developer_mdm_package_config_policy" "npm_secure_registry" {
  name        = "npm secure registry"
  description = "Route npm installs through the StepSecurity secure registry"
}

# Combined: the StepSecurity registry plus extra .npmrc keys. Omitting registry_type keeps
# the StepSecurity registry -- adding settings never silently opts a policy out of it.
resource "stepsecurity_developer_mdm_package_config_policy" "npm_combined" {
  name        = "npm secure registry with settings"
  description = "StepSecurity registry plus shared npm client settings"

  settings = {
    "fetch-retries"      = "3"
    "audit"              = "false"
    "@internal:registry" = "https://registry.example.com/npm/"
  }
}

# Settings-only: no StepSecurity registry at all, which has to be selected explicitly with
# registry_type = "none". The settings then have to define the registry themselves.
#
# "$${EXAMPLE_NPM_TOKEN}" is escaped HCL: Terraform writes the literal string
# "${EXAMPLE_NPM_TOKEN}" into .npmrc, and the device's npm resolves it from the environment
# at install time. Do not interpolate a real credential here -- policy authoring spec is
# stored in Terraform state.
resource "stepsecurity_developer_mdm_package_config_policy" "npm_settings_only" {
  name          = "npm third-party registry"
  description   = "Default registry served by a third party, with a scoped override"
  registry_type = "none"

  settings = {
    "registry"                               = "https://registry.example.com/npm/"
    "@example:registry"                      = "https://registry.example.com/npm/"
    "//registry.example.com/npm/:_authToken" = "$${EXAMPLE_NPM_TOKEN}"
    "fetch-retries"                          = "3"
  }
}

# PyPI. clients is required and accepts pip and uv; registry_type defaults to stepsecurity,
# which is the only value the API accepts for pypi today.
resource "stepsecurity_developer_mdm_package_config_policy" "pypi" {
  name        = "Python packages"
  description = "Route pip and uv installs through the StepSecurity secure registry"
  target      = "pypi"
  clients     = ["pip", "uv"]
}

# Go. The module proxy is configured from the StepSecurity registry; there is nothing else
# to select, so only the target changes.
resource "stepsecurity_developer_mdm_package_config_policy" "go" {
  name        = "Go packages"
  description = "Route go module downloads through the StepSecurity secure registry"
  target      = "go"
}

# A policy on its own enforces nothing; it has to be bundled into a profile and assigned.
# This profile uses enforcement = "dmg" so the agent writes the managed config itself. "mdm"
# is also valid for this category, with the package script deployed through the console and
# the agent only verifying what it observes -- but Terraform cannot export that script,
# because the compiled artifact embeds the tenant's registry auth key.
#
# A profile carries at most one policy per ecosystem, so the npm policies above are
# alternatives: pick one. Assign explicit device IDs rather than the whole fleet.
resource "stepsecurity_developer_mdm_profile" "packages" {
  name        = "package configuration"
  enforcement = "dmg"

  policy_ids = [
    stepsecurity_developer_mdm_package_config_policy.npm_combined.policy_id,
    stepsecurity_developer_mdm_package_config_policy.pypi.policy_id,
    stepsecurity_developer_mdm_package_config_policy.go.policy_id,
  ]

  assignment = {
    device_ids = ["REPLACE_WITH_DEVICE_ID"]
  }
}
