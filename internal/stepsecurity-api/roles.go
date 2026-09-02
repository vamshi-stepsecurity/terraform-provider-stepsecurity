package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Permission is the user-facing (resource, action) pair. The API stores
// permissions on the wire as a single canonical string ("<resource>-<action>")
// — see decodePermission / encodePermissions for the round-trip.
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// Role represents a custom role defined by a customer. System roles
// (admin, auditor) are also returned by ListRoles but are NOT manageable
// through this resource (IsSystem will be true and the API rejects writes).
type Role struct {
	ID          string       `json:"id,omitempty"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
	IsSystem    bool         `json:"is_system,omitempty"`
	UpdatedAt   int64        `json:"updated_at,omitempty"`
	UpdatedBy   string       `json:"updated_by,omitempty"`
}

// CreateRoleRequest is the payload accepted by POST /v1/:customer/roles.
type CreateRoleRequest struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// UpdateRoleRequest is the payload accepted by PUT /v1/:customer/roles/:role_id.
// The role's UUID is supplied separately as the path parameter; renaming is
// supported by setting Name to the new value.
type UpdateRoleRequest struct {
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// roleAPIResponse mirrors the wire format. Permissions come back as flat
// "<resource>-<action>" strings; we decode them into Permission structs so
// callers see a structured type.
type roleAPIResponse struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	IsSystem    bool     `json:"is_system,omitempty"`
	UpdatedAt   int64    `json:"updated_at,omitempty"`
	UpdatedBy   string   `json:"updated_by,omitempty"`
}

type listRolesResponse struct {
	Roles []roleAPIResponse `json:"roles"`
}

func (c *APIClient) ListRoles(ctx context.Context) ([]Role, error) {
	URI := fmt.Sprintf("%s/v1/%s/roles", c.BaseURL, c.Customer)
	body, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	var parsed listRolesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles list: %w", err)
	}

	out := make([]Role, 0, len(parsed.Roles))
	for _, r := range parsed.Roles {
		out = append(out, fromAPIResponse(r))
	}
	return out, nil
}

func (c *APIClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	URI := fmt.Sprintf("%s/v1/%s/roles", c.BaseURL, c.Customer)
	body, err := c.post(ctx, URI, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	var resp roleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal create role response: %w", err)
	}
	role := fromAPIResponse(resp)
	return &role, nil
}

func (c *APIClient) GetRole(ctx context.Context, roleID string) (*Role, error) {
	URI := fmt.Sprintf("%s/v1/%s/roles/%s", c.BaseURL, c.Customer, roleID)
	body, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	var resp roleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal role: %w", err)
	}
	role := fromAPIResponse(resp)
	return &role, nil
}

func (c *APIClient) UpdateRole(ctx context.Context, roleID string, req UpdateRoleRequest) (*Role, error) {
	URI := fmt.Sprintf("%s/v1/%s/roles/%s", c.BaseURL, c.Customer, roleID)
	body, err := c.put(ctx, URI, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	var resp roleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal update role response: %w", err)
	}
	role := fromAPIResponse(resp)
	return &role, nil
}

func (c *APIClient) DeleteRole(ctx context.Context, roleID string) error {
	URI := fmt.Sprintf("%s/v1/%s/roles/%s", c.BaseURL, c.Customer, roleID)
	if _, err := c.delete(ctx, URI); err != nil {
		// The API returns 409 Conflict when a role is still assigned to users.
		// Surface that error verbatim so operators can fix the assignment
		// before retrying terraform destroy / replace.
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

// FeatureCatalog represents the response from GET /v1/:customer/permissions —
// the grouped (feature → resources) catalog the console renders. Useful to
// validate user-supplied permission entries against the known resource list
// without hardcoding it in the provider.
type FeatureCatalog struct {
	Features []FeatureGroup `json:"features"`
}

type FeatureGroup struct {
	Name      string            `json:"name"`
	Resources []CatalogResource `json:"resources"`
}

type CatalogResource struct {
	Resource    string   `json:"resource"`
	Feature     string   `json:"feature"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
}

func (c *APIClient) GetPermissionCatalog(ctx context.Context) (*FeatureCatalog, error) {
	URI := fmt.Sprintf("%s/v1/%s/permissions", c.BaseURL, c.Customer)
	body, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission catalog: %w", err)
	}

	var resp FeatureCatalog
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permission catalog: %w", err)
	}
	return &resp, nil
}

// decodePermission splits the canonical wire form "<resource>-<action>" back
// into a Permission struct. Action is whatever follows the LAST "-" so
// resources with hyphens (e.g. "developer-mdm-read") parse correctly.
func decodePermission(s string) (Permission, bool) {
	idx := strings.LastIndex(s, "-")
	if idx <= 0 || idx == len(s)-1 {
		return Permission{}, false
	}
	return Permission{Resource: s[:idx], Action: s[idx+1:]}, true
}

// fromAPIResponse converts the wire shape into the user-facing Role.
// Decoding is lenient: unparseable entries (which shouldn't happen if the
// server validates) are silently dropped rather than failing the read.
func fromAPIResponse(r roleAPIResponse) Role {
	perms := make([]Permission, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		if perm, ok := decodePermission(p); ok {
			perms = append(perms, perm)
		}
	}
	return Role{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: perms,
		IsSystem:    r.IsSystem,
		UpdatedAt:   r.UpdatedAt,
		UpdatedBy:   r.UpdatedBy,
	}
}
