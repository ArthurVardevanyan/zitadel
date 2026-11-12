package app

import (
	"context"

	"connectrpc.com/connect"

	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/application/v2"
)

// Workload identity federation methods. Implemented in the corresponding
// command/query layers; see feat/wif commit series.

func (s *Server) AddWorkloadIdentityFederation(context.Context, *connect.Request[application.AddApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.AddApplicationWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "APP-v2wif1", "Errors.Unimplemented")
}

func (s *Server) UpdateWorkloadIdentityFederation(context.Context, *connect.Request[application.UpdateApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.UpdateApplicationWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "APP-v2wif2", "Errors.Unimplemented")
}

func (s *Server) RemoveWorkloadIdentityFederation(context.Context, *connect.Request[application.RemoveApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.RemoveApplicationWorkloadIdentityFederationResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "APP-v2wif3", "Errors.Unimplemented")
}

func (s *Server) ListWorkloadIdentityFederations(context.Context, *connect.Request[application.ListApplicationWorkloadIdentityFederationsRequest]) (*connect.Response[application.ListApplicationWorkloadIdentityFederationsResponse], error) {
	return nil, zerrors.ThrowUnimplemented(nil, "APP-v2wif4", "Errors.Unimplemented")
}
