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

# Compiles the import artifact for a profile on macOS. This is a read-only
# data source and creates no remote object.
data "stepsecurity_developer_mdm_profile_export" "macos" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "macos"
}

# `content` is the decoded artifact body; pass it directly to local_file.content.
output "export_filename" {
  value = data.stepsecurity_developer_mdm_profile_export.macos.filename
}
