package user

import (
	"context"

	"connectrpc.com/connect"

	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/user/v2"
)

// Workload identity federation methods. Implemented in the corresponding
// command/query layers; see feat/wif commit series.

func (s *Server) AddWorkloadIdentityFederation(context.Context, *connect.Request[user.AddWorkloadIdentityFederationRequest]) (*connect.Response[user.AddWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "USER-v2wif1", "Errors.Unimplemented")
}

func (s *Server) UpdateWorkloadIdentityFederation(context.Context, *connect.Request[user.UpdateWorkloadIdentityFederationRequest]) (*connect.Response[user.UpdateWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "USER-v2wif2", "Errors.Unimplemented")
}

func (s *Server) RemoveWorkloadIdentityFederation(context.Context, *connect.Request[user.RemoveWorkloadIdentityFederationRequest]) (*connect.Response[user.RemoveWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "USER-v2wif3", "Errors.Unimplemented")
}

func (s *Server) ListWorkloadIdentityFederations(context.Context, *connect.Request[user.ListWorkloadIdentityFederationsRequest]) (*connect.Response[user.ListWorkloadIdentityFederationsResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "USER-v2wif4", "Errors.Unimplemented")
}
