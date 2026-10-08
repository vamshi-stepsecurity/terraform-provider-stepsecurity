#!/bin/bash

# Developer MDM package config policies can be imported using the policy ID.
# Format: <policy_id>

terraform import stepsecurity_developer_mdm_package_config_policy.npm_secure_registry POLICY_ID

# The configuration you import into has to spell out the registry selection: a settings-only
# npm policy reads back as registry_type = "none", so the HCL needs that value explicitly for
# the first plan to come back with no changes. Every other shape defaults to "stepsecurity".
