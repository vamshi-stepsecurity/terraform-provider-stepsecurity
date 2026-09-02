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

# Read runtime compliance for all devices governed by a profile. This is
# read-only observability; compliance state changes outside Terraform and does
# not drive resource drift.
data "stepsecurity_developer_mdm_profile_compliance" "example" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
}

output "profile_compliance" {
  value = data.stepsecurity_developer_mdm_profile_compliance.example.compliance
}
