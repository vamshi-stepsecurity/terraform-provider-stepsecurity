package provider

import (
	"context"
	"encoding/json"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestDeveloperMDMDeviceComplianceDataSource_Schema(t *testing.T) {
	t.Parallel()

	resp := &fwdatasource.SchemaResponse{}
	NewDeveloperMDMDeviceComplianceDataSource().Schema(context.Background(), fwdatasource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	attrs := resp.Schema.Attributes
	assert.Contains(t, attrs, "device_id")
	assert.Contains(t, attrs, "compliance")
}

func TestDeveloperMDMDeviceComplianceDataSource_Read(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.On("GetDeveloperMDMDeviceCompliance", mock.Anything, "dev1").Return(&stepsecurityapi.DeveloperMDMDeviceComplianceResponse{
		DeviceID: "dev1",
		Compliance: []stepsecurityapi.DeveloperMDMComplianceView{
			{DeviceID: "dev1", Category: "ide_extension", Target: "vscode", State: "compliant", LastSeenAt: 1780000000, Platform: "darwin"},
		},
	}, nil).Once()

	d := &developerMDMDeviceComplianceDataSource{client: mockClient}

	resp := &fwdatasource.SchemaResponse{}
	d.Schema(ctx, fwdatasource.SchemaRequest{}, resp)
	schema := resp.Schema

	state := tfsdk.State{Schema: schema}
	require.False(t, state.Set(ctx, developerMDMDeviceComplianceDataSourceModel{
		DeviceID:   types.StringValue("dev1"),
		Compliance: types.ListNull(types.ObjectType{AttrTypes: developerMDMComplianceAttrTypes}),
	}).HasError())

	readReq := fwdatasource.ReadRequest{Config: tfsdk.Config{Raw: state.Raw, Schema: schema}}
	readResp := &fwdatasource.ReadResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, readReq, readResp)
	require.False(t, readResp.Diagnostics.HasError(), "read errors: %v", readResp.Diagnostics)
	mockClient.AssertExpectations(t)

	var got developerMDMDeviceComplianceDataSourceModel
	require.False(t, readResp.State.Get(ctx, &got).HasError())

	var rows []developerMDMComplianceRowModel
	require.False(t, got.Compliance.ElementsAs(ctx, &rows, false).HasError())
	require.Len(t, rows, 1)
	assert.Equal(t, "vscode", rows[0].Target.ValueString())
	assert.Equal(t, "compliant", rows[0].State.ValueString())
	assert.Equal(t, int64(1780000000), rows[0].LastSeenAt.ValueInt64())
	assert.Equal(t, "darwin", rows[0].Platform.ValueString())
}

func TestDeveloperMDMComplianceListValue_EnforcementAndDiff(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const diff = `{"changes":[{"path":"extensions.allowed","op":"set_diff","missing":{"ms-python.python":true}}]}`

	rows := []stepsecurityapi.DeveloperMDMComplianceView{
		{
			DeviceID:             "dev1",
			State:                "mdm_drift",
			EvaluatedEnforcement: "mdm",
			Diff:                 json.RawMessage(diff),
		},
		{
			DeviceID:             "dev2",
			State:                "compliant",
			EvaluatedEnforcement: "dmg",
		},
	}

	listValue, diags := developerMDMComplianceListValue(rows)
	require.False(t, diags.HasError(), "list errors: %v", diags)

	var got []developerMDMComplianceRowModel
	require.False(t, listValue.ElementsAs(ctx, &got, false).HasError())
	require.Len(t, got, 2)

	assert.Equal(t, "mdm", got[0].EvaluatedEnforcement.ValueString())
	assert.Equal(t, diff, got[0].DiffJSON.ValueString(), "the diff must be passed through verbatim")

	assert.Equal(t, "dmg", got[1].EvaluatedEnforcement.ValueString())
	assert.True(t, got[1].DiffJSON.IsNull(), "a row with no diff must be null, not an empty string")
}
