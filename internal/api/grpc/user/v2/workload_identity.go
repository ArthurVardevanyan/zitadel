package user

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
	"github.com/zitadel/zitadel/pkg/grpc/user/v2"
)

func (s *Server) AddWorkloadIdentityFederation(ctx context.Context, req *connect.Request[user.AddWorkloadIdentityFederationRequest]) (*connect.Response[user.AddWorkloadIdentityFederationResponse], error) {
	wif, err := wif_convert.WorkloadIdentityCreateRequestToModel(req.Msg)
	if err != nil {
		return nil, err
	}
	wif.OwnerType = domain.WorkloadIdentityOwnerTypeServiceUser
	wif.OwnerID = req.Msg.GetUserId()
	wif.PermissionCheck = s.command.NewPermissionCheckUserWrite(ctx, true)

	details, err := s.command.AddWorkloadIdentityFederation(ctx, wif)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&user.AddWorkloadIdentityFederationResponse{
		Id:      wif.AggregateID,
		Details: object.DomainToDetailsPb(details),
	}), nil
}

func (s *Server) UpdateWorkloadIdentityFederation(ctx context.Context, req *connect.Request[user.UpdateWorkloadIdentityFederationRequest]) (*connect.Response[user.UpdateWorkloadIdentityFederationResponse], error) {
	wif, err := wif_convert.WorkloadIdentityUpdateRequestToModel(req.Msg)
	if err != nil {
		return nil, err
	}
	wif.OwnerType = domain.WorkloadIdentityOwnerTypeServiceUser
	wif.OwnerID = req.Msg.GetUserId()
	wif.PermissionCheck = s.command.NewPermissionCheckUserWrite(ctx, true)

	details, err := s.command.UpdateWorkloadIdentityFederation(ctx, wif)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&user.UpdateWorkloadIdentityFederationResponse{
		Details: object.DomainToDetailsPb(details),
	}), nil
}

func (s *Server) RemoveWorkloadIdentityFederation(ctx context.Context, req *connect.Request[user.RemoveWorkloadIdentityFederationRequest]) (*connect.Response[user.RemoveWorkloadIdentityFederationResponse], error) {
	details, err := s.command.RemoveWorkloadIdentityFederation(ctx, &command.WorkloadIdentity{
		ObjectRoot: models.ObjectRoot{
			AggregateID: req.Msg.GetId(),
		},
		PermissionCheck: s.command.NewPermissionCheckUserWrite(ctx, true),
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&user.RemoveWorkloadIdentityFederationResponse{
		DeletionDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) ListWorkloadIdentityFederations(ctx context.Context, req *connect.Request[user.ListWorkloadIdentityFederationsRequest]) (*connect.Response[user.ListWorkloadIdentityFederationsResponse], error) {
	// the owner keyed query itself is not permission filtered, so check the
	// user (existence and permission) first
	if _, err := s.query.GetUserByIDWithPermission(ctx, false, req.Msg.GetUserId(), s.checkPermission); err != nil {
		return nil, err
	}

	offset, limit, _, err := filter.PaginationPbToQuery(s.systemDefaults, req.Msg.GetPagination())
	if err != nil {
		return nil, err
	}

	identities, err := s.query.WorkloadIdentitiesByOwner(ctx, domain.WorkloadIdentityOwnerTypeServiceUser, req.Msg.GetUserId())
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&user.ListWorkloadIdentityFederationsResponse{
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
