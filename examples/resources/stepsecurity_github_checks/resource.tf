
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

# github PR checks configuration with different types of controls applied across different repositories in a github organization
resource "stepsecurity_github_checks" "test-organization" {
  owner              = "test-organization"
  custom_description = "Checks created by StepSecurity. To approve failed checks, please contact secops admins user1@company.com, user2@company.com" # optional: appended to all check summaries
  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period                     = 3
        packages_to_exempt_in_cooldown_check = ["test-package/*"]
      }
    },
    {
      control = "PyPI Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period                     = 4
        packages_to_exempt_in_cooldown_check = ["my-internal-package"] # exempted package name must be as per PEP 503 normalization
      }
    },
    {
      control = "PyPI Package Compromised Updates"
      enable  = true
      type    = "required"
    },
    {
      control = "Script Injection"
      enable  = true
      type    = "optional"
    }
  ]
  required_checks = {
    repos = ["*"] # applies to all repositories in the organization
  }
  optional_checks = {
    repos = ["test-repo-1"] # applies to only test-repo-1
  }
  baseline_check = {
    repos      = ["*"]           # applies to all repositories in the organization
    omit_repos = ["test-repo-2"] # omits test-repo-2 from baseline check
  }

}

# For importing existing github checks of a github organization to terraform state
# this will be helpful to manage already set github checks using terraform
# alternative to this is to use terraform import command
import {
  to = stepsecurity_github_checks.test-organization
  id = "test-organization"
}

# github PR checks configuration with PyPI controls
resource "stepsecurity_github_checks" "test-organization-pypi" {
  owner = "test-organization"
  controls = [
    {
      control = "PyPI Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period                     = 3
        packages_to_exempt_in_cooldown_check = ["my-internal-package"]
      }
    },
    {
      control = "PyPI Package Compromised Updates"
      enable  = true
      type    = "required"
    }
  ]
  required_checks = {
    repos = ["*"] # applies to all repositories in the organization
  }
}

# github PR checks configuration with Maven controls
resource "stepsecurity_github_checks" "test-organization-maven" {
  owner = "test-organization"
  controls = [
    {
      control = "Maven Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period                     = 3
        packages_to_exempt_in_cooldown_check = ["com.mycompany:internal-lib"]
      }
    },
    {
      control = "Maven Package Compromised Updates"
      enable  = true
      type    = "required"
    }
  ]
  required_checks = {
    repos = ["*"] # applies to all repositories in the organization
  }
}

# github PR checks configuration with NuGet controls
resource "stepsecurity_github_checks" "test-organization-nuget" {
  owner = "test-organization"
  controls = [
    {
      control = "NuGet Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period                     = 3
        packages_to_exempt_in_cooldown_check = ["MyCompany.Internal.Lib"]
      }
    },
    {
      control = "NuGet Package Compromised Updates"
      enable  = true
      type    = "required"
    }
  ]
  required_checks = {
    repos = ["*"] # applies to all repositories in the organization
  }
}