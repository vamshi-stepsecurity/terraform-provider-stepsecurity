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

# A policy on its own enforces nothing; it has to be bundled into a profile and assigned.
# This profile uses enforcement = "dmg" so the agent writes .npmrc itself. "mdm" is also
# valid for this category, with the package script deployed through the console and the
# agent only verifying what it observes — but Terraform cannot export that script, because
# the compiled artifact embeds the tenant's registry auth key.
resource "stepsecurity_developer_mdm_profile" "npm_secure_registry" {
  name        = "npm secure registry"
  enforcement = "dmg"

  policy_ids = [
    stepsecurity_developer_mdm_package_config_policy.npm_secure_registry.policy_id,
  ]

  assignment = {
    all_devices = true
  }
}
