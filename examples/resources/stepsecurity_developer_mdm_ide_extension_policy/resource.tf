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

# Allowlist permitting only the listed VS Code extensions; everything else is blocked.
resource "stepsecurity_developer_mdm_ide_extension_policy" "engineering_vscode" {
  name        = "Engineering VS Code allowlist"
  description = "Only approved extensions for engineering workstations"
  mode        = "allowlist"

  rules = [
    { publisher = "ms-python", name = "python", stable = true, comment = "Approved for the data-science org" }, # stable channel
    { publisher = "github" },                                                                                   # whole publisher
    { publisher = "redhat", name = "vscode-yaml", versions = ["1.15.0"] },                                      # pinned version
  ]
}

# Points VS Code at a private extension marketplace instead of the public one. The URL is
# independent of mode, so it works on a blocklist just as well as on an allowlist.
resource "stepsecurity_developer_mdm_ide_extension_policy" "private_marketplace" {
  name        = "Private marketplace"
  description = "Resolve extension browsing and installs against the internal gallery"
  mode        = "blocklist"

  gallery_service_url = "https://gallery.example.com/_apis/public/gallery"

  rules = [
    { publisher = "unapproved-publisher", comment = "Blocked pending security review" },
  ]
}

# Delivering the private marketplace through an MDM you already run. On the "mdm" channel
# the StepSecurity agent never writes, so the artifact below is what actually configures
# the device; StepSecurity reports drift against it.
resource "stepsecurity_developer_mdm_profile" "private_marketplace" {
  name        = "Private marketplace"
  enforcement = "mdm"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.private_marketplace.policy_id,
  ]
}

# The bare macOS preferences file, for MDMs that take a preference domain plus a plist.
# Jamf and Intune need preference_domain alongside it. Omit format for the full
# .mobileconfig profile instead.
data "stepsecurity_developer_mdm_profile_export" "private_marketplace_macos" {
  profile_id = stepsecurity_developer_mdm_profile.private_marketplace.profile_id
  os         = "macos"
  format     = "plist"
}
