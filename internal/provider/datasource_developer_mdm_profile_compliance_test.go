package provider

import (
	"context"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestDeveloperMDMProfileComplianceDataSource_Schema(t *testing.T) {
	t.Parallel()

	resp := &fwdatasource.SchemaResponse{}
	NewDeveloperMDMProfileComplianceDataSource().Schema(context.Background(), fwdatasource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	attrs := resp.Schema.Attributes
	assert.Contains(t, attrs, "profile_id")
	assert.Contains(t, attrs, "compliance")
}

func TestDeveloperMDMProfileComplianceDataSource_Read(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.On("GetDeveloperMDMProfileCompliance", mock.Anything, "prof1").Return(&stepsecurityapi.DeveloperMDMProfileComplianceResponse{
		ProfileID: "prof1",
		Compliance: []stepsecurityapi.DeveloperMDMComplianceView{
			{DeviceID: "dev1", Category: "ide_extension", Target: "vscode", ProfileID: "prof1", State: "pending"},
		},
	}, nil).Once()

	d := &developerMDMProfileComplianceDataSource{client: mockClient}

	resp := &fwdatasource.SchemaResponse{}
	d.Schema(ctx, fwdatasource.SchemaRequest{}, resp)
	schema := resp.Schema

	state := tfsdk.State{Schema: schema}
	require.False(t, state.Set(ctx, developerMDMProfileComplianceDataSourceModel{
		ProfileID:  types.StringValue("prof1"),
		Compliance: types.ListNull(types.ObjectType{AttrTypes: developerMDMComplianceAttrTypes}),
	}).HasError())

	readReq := fwdatasource.ReadRequest{Config: tfsdk.Config{Raw: state.Raw, Schema: schema}}
	readResp := &fwdatasource.ReadResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, readReq, readResp)
	require.False(t, readResp.Diagnostics.HasError(), "read errors: %v", readResp.Diagnostics)
	mockClient.AssertExpectations(t)

	var got developerMDMProfileComplianceDataSourceModel
	require.False(t, readResp.State.Get(ctx, &got).HasError())

	var rows []developerMDMComplianceRowModel
	require.False(t, got.Compliance.ElementsAs(ctx, &rows, false).HasError())
	require.Len(t, rows, 1)
	assert.Equal(t, "vscode", rows[0].Target.ValueString())
	assert.Equal(t, "pending", rows[0].State.ValueString())
	assert.Equal(t, "prof1", rows[0].ProfileID.ValueString())
}
