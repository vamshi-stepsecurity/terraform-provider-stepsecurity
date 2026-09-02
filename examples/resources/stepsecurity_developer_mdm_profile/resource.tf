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

resource "stepsecurity_developer_mdm_ide_extension_policy" "engineering_vscode" {
  name = "Engineering VS Code allowlist"
  mode = "allowlist"

  rules = [
    { publisher = "ms-python", name = "python", stable = true },
  ]
}

# Bundles one or more policies into a profile and assigns it to all devices.
resource "stepsecurity_developer_mdm_profile" "engineering" {
  name        = "Engineering"
  description = "Approved IDE extensions for engineering"

  # "dmg" lets the StepSecurity agent write the managed configuration; "mdm" is verify-only,
  # for fleets whose own MDM delivers it. Applies to every policy in the profile.
  enforcement = "dmg"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.engineering_vscode.policy_id,
  ]

  assignment = {
    all_devices = true
  }
}
