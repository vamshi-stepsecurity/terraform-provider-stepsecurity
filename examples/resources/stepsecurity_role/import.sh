#!/bin/bash

# Roles can be imported using the role's UUID.
# The UUID is visible in the console (Admin Console → Roles)
# or via `GET /v1/{customer}/roles`.
terraform import stepsecurity_role.developer 00000000-0000-0000-0000-000000000000
