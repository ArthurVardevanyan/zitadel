package app

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/api/grpc/filter/v2"
	"github.com/zitadel/zitadel/internal/api/grpc/object/v2"
	wif_convert "github.com/zitadel/zitadel/internal/api/grpc/workload_identity/v2/convert"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/application/v2"
)

// checkWIFFeatureFlag rejects the federation methods while the
// WorkloadIdentityFederation system config flag is disabled (dark launch).
func (s *Server) checkWIFFeatureFlag() error {
	if s.wifEnabled {
		return nil
	}
	return zerrors.ThrowUnimplemented(nil, "APP-v2wif1", "Errors.WorkloadIdentity.Disabled")
}

func (s *Server) AddWorkloadIdentityFederation(ctx context.Context, req *connect.Request[application.AddApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.AddApplicationWorkloadIdentityFederationResponse], error) {
	if err := s.checkWIFFeatureFlag(); err != nil {
		return nil, err
	}

	wif, err := wif_convert.WorkloadIdentityCreateRequestToModel(req.Msg)
	if err != nil {
		return nil, err
	}
	wif.OwnerType = domain.WorkloadIdentityOwnerTypeApp
	wif.OwnerID = req.Msg.GetApplicationId()
	wif.ProjectID = req.Msg.GetProjectId()

	details, err := s.command.AddWorkloadIdentityFederation(ctx, wif)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&application.AddApplicationWorkloadIdentityFederationResponse{
		Id:      wif.AggregateID,
		Details: object.DomainToDetailsPb(details),
	}), nil
}

func (s *Server) UpdateWorkloadIdentityFederation(ctx context.Context, req *connect.Request[application.UpdateApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.UpdateApplicationWorkloadIdentityFederationResponse], error) {
	if err := s.checkWIFFeatureFlag(); err != nil {
		return nil, err
	}

	wif, err := wif_convert.WorkloadIdentityUpdateRequestToModel(req.Msg)
	if err != nil {
		return nil, err
	}
	wif.OwnerType = domain.WorkloadIdentityOwnerTypeApp
	wif.OwnerID = req.Msg.GetApplicationId()
	wif.ProjectID = req.Msg.GetProjectId()

	details, err := s.command.UpdateWorkloadIdentityFederation(ctx, wif)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&application.UpdateApplicationWorkloadIdentityFederationResponse{
		Details: object.DomainToDetailsPb(details),
	}), nil
}

func (s *Server) RemoveWorkloadIdentityFederation(ctx context.Context, req *connect.Request[application.RemoveApplicationWorkloadIdentityFederationRequest]) (*connect.Response[application.RemoveApplicationWorkloadIdentityFederationResponse], error) {
	if err := s.checkWIFFeatureFlag(); err != nil {
		return nil, err
	}

	details, err := s.command.RemoveWorkloadIdentityFederation(ctx, &command.WorkloadIdentity{
		ObjectRoot: models.ObjectRoot{
			AggregateID: req.Msg.GetId(),
		},
		ProjectID: req.Msg.GetProjectId(),
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&application.RemoveApplicationWorkloadIdentityFederationResponse{
		DeletionDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) ListWorkloadIdentityFederations(ctx context.Context, req *connect.Request[application.ListApplicationWorkloadIdentityFederationsRequest]) (*connect.Response[application.ListApplicationWorkloadIdentityFederationsResponse], error) {
	if err := s.checkWIFFeatureFlag(); err != nil {
		return nil, err
	}

	// the owner keyed query itself is not permission filtered, so check the
	// application (existence and permission) first, mirroring GetApplication
	if _, err := s.query.AppByIDWithPermission(ctx, req.Msg.GetApplicationId(), false, s.checkPermission); err != nil {
		return nil, err
	}

	offset, limit, _, err := filter.PaginationPbToQuery(s.systemDefaults, req.Msg.GetPagination())
	if err != nil {
		return nil, err
	}

	identities, err := s.query.WorkloadIdentitiesByOwner(ctx, domain.WorkloadIdentityOwnerTypeApp, req.Msg.GetApplicationId())
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&application.ListApplicationWorkloadIdentityFederationsResponse{
		Federations: wif_convert.WorkloadIdentitiesToPb(workloadIdentityPage(identities, offset, limit)),
		Pagination:  filter.QueryToPaginationPb(query.SearchRequest{Offset: offset, Limit: limit}, query.SearchResponse{Count: uint64(len(identities))}),
	}), nil
}

// workloadIdentityPage applies offset and limit to the configurations of a
// single owner. The set per owner is small and bounded, so pagination is done
// in memory instead of extending the projection query.
func workloadIdentityPage(identities []*query.WorkloadIdentity, offset, limit uint64) []*query.WorkloadIdentity {
	if offset >= uint64(len(identities)) {
		return nil
	}
	return identities[offset:min(offset+limit, uint64(len(identities)))]
}
