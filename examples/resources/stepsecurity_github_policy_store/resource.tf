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

# Policy with block mode and basic endpoints
resource "stepsecurity_github_policy_store" "audit-policy" {
  owner         = "test-organization"
  policy_name   = "audit-policy"
  egress_policy = "block"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443"
  ]
}

# Policy with audit mode and custom endpoints
resource "stepsecurity_github_policy_store" "custom-policy" {
  owner         = "test-organization"
  policy_name   = "custom-policy"
  egress_policy = "audit"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443",
    "docker.io:443"
  ]
}

# Policy with block mode and a deny list instead of an allow list.
# denied_endpoints cannot be set together with allowed_endpoints.
resource "stepsecurity_github_policy_store" "denied-endpoints-policy" {
  owner         = "test-organization"
  policy_name   = "denied-endpoints-policy"
  egress_policy = "block"
  denied_endpoints = [
    "evil.example.com:443",
    "malware.example.org:443"
  ]
}

# Policy with lockdown enabled for all detections
resource "stepsecurity_github_policy_store" "lockdown-all" {
  owner         = "test-organization"
  policy_name   = "lockdown-all-policy"
  egress_policy = "block"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
  ]

  lockdown = {
    enabled                   = true
    privileged_container      = true
    runner_worker_memory_read = true
    reverse_shell             = true
  }
}

# Policy with lockdown enabled for selected detections only
resource "stepsecurity_github_policy_store" "lockdown-selective" {
  owner         = "test-organization"
  policy_name   = "lockdown-selective-policy"
  egress_policy = "block"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
  ]

  lockdown = {
    enabled       = true
    reverse_shell = true
  }
}

# For importing existing github policy store policies to terraform state
import {
  to = stepsecurity_github_policy_store.audit-policy
  id = "test-organization:::audit-policy" # format is <owner>:::<policy_name>
}
