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

# Enable all controls for the npm registry
resource "stepsecurity_secure_registry_policy" "npm_full" {
  registry = "npm"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
    exemption_list = ["@babel/core@*", "react@1.2.3", "@scope/*", "lodash@4.17.21"]
  }

  compromised_packages_control = {
    enabled = true
  }

  typosquatting_control = {
    enabled        = true
    exemption_list = ["reactt", "lodashh"]
  }

  custom_block_list_control = {
    enabled  = true
    patterns = ["lodash@4.17.20", "@scope/*", "left-pad@*"]
  }

  npm_settings = {
    rewrite_tarball_urls = true
  }
}

# Enable only the compromised packages control
resource "stepsecurity_secure_registry_policy" "npm_compromised_only" {
  registry = "npm"

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the cooldown control with no exemptions
resource "stepsecurity_secure_registry_policy" "npm_cooldown_only" {
  registry = "npm"

  cooldown_control = {
    enabled        = true
    period_in_days = 3
  }
}

# For importing an existing npm registry policy into Terraform state
# alternative to this is to use the terraform import command
import {
  to = stepsecurity_secure_registry_policy.npm_full
  id = "npm"
}

# Enable all controls for the PyPI registry (npm_settings is npm-only, omitted here)
resource "stepsecurity_secure_registry_policy" "pypi_full" {
  registry = "pypi"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
    exemption_list = ["requests@*", "django@1.*", "flask@3.0.3"]
  }

  compromised_packages_control = {
    enabled = true
  }

  custom_block_list_control = {
    enabled  = false
    patterns = ["requests@2.25.0", "insecure-package@*"]
  }
}

# Enable only the compromised packages control for PyPI
resource "stepsecurity_secure_registry_policy" "pypi_compromised_only" {
  registry = "pypi"

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the cooldown control for PyPI with no exemptions
resource "stepsecurity_secure_registry_policy" "pypi_cooldown_only" {
  registry = "pypi"

  cooldown_control = {
    enabled        = true
    period_in_days = 3
  }
}

# For importing an existing PyPI registry policy into Terraform state
import {
  to = stepsecurity_secure_registry_policy.pypi_full
  id = "pypi"
}

# Enable cooldown and compromised packages controls for Maven Central
# (custom_block_list_control, typosquatting_control, and npm_settings are not applicable to maven)
resource "stepsecurity_secure_registry_policy" "maven_full" {
  registry = "maven"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
  }

  compromised_packages_control = {
    enabled = true
  }
}

# For importing an existing Maven registry policy into Terraform state
import {
  to = stepsecurity_secure_registry_policy.maven_full
  id = "maven"
}

# Enable all applicable controls for NuGet
# (typosquatting_control and npm_settings are not applicable to nuget)
resource "stepsecurity_secure_registry_policy" "nuget_full" {
  registry = "nuget"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
  }

  compromised_packages_control = {
    enabled = true
  }

  custom_block_list_control = {
    enabled  = true
    patterns = ["Newtonsoft.Json@1*"]
  }
}

# For importing an existing NuGet registry policy into Terraform state
import {
  to = stepsecurity_secure_registry_policy.nuget_full
  id = "nuget"
}
