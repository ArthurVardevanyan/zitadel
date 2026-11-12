package app

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/application/v2"
)

// While the WorkloadIdentityFederation flag is disabled the management
// methods must answer Unimplemented without touching command or query.
func TestServerWorkloadIdentityFederationDisabled(t *testing.T) {
	s := new(Server)
	_, err := s.AddWorkloadIdentityFederation(context.Background(), connect.NewRequest(&application.AddApplicationWorkloadIdentityFederationRequest{}))
	assert.True(t, zerrors.IsUnimplemented(err), "AddWorkloadIdentityFederation: %v", err)

	_, err = s.UpdateWorkloadIdentityFederation(context.Background(), connect.NewRequest(&application.UpdateApplicationWorkloadIdentityFederationRequest{}))
	assert.True(t, zerrors.IsUnimplemented(err), "UpdateWorkloadIdentityFederation: %v", err)

	_, err = s.RemoveWorkloadIdentityFederation(context.Background(), connect.NewRequest(&application.RemoveApplicationWorkloadIdentityFederationRequest{}))
	assert.True(t, zerrors.IsUnimplemented(err), "RemoveWorkloadIdentityFederation: %v", err)

	_, err = s.ListWorkloadIdentityFederations(context.Background(), connect.NewRequest(&application.ListApplicationWorkloadIdentityFederationsRequest{}))
	assert.True(t, zerrors.IsUnimplemented(err), "ListWorkloadIdentityFederations: %v", err)

	// sanity: the guard lets the enabled server pass through
	s.wifEnabled = true
	require.NoError(t, s.checkWIFFeatureFlag())
}
