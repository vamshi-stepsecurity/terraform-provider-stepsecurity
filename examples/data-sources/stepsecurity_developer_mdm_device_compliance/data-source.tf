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

# Read runtime compliance for a single device. This is read-only observability;
# compliance state changes outside Terraform and does not drive resource drift.
data "stepsecurity_developer_mdm_device_compliance" "example" {
  device_id = "device-1"
}

output "device_compliance" {
  value = data.stepsecurity_developer_mdm_device_compliance.example.compliance
}
