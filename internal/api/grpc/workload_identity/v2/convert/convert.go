// Package convert maps workload identity federation messages between the
// application.v2 and user.v2 gRPC APIs and the command/query layers. The
// request interfaces below are satisfied by the Add and Update request
// messages of both services, which share the identical configuration fields.
package convert

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
	wif_pb "github.com/zitadel/zitadel/pkg/grpc/workload_identity/v2"
)

// CreateRequest is implemented by AddWorkloadIdentityFederationRequest of
// both zitadel.application.v2 and zitadel.user.v2.
type CreateRequest interface {
	GetName() string
	GetIssuer() string
	GetJwksUri() string
	GetAudiences() []string
	GetSubjectConditions() []*wif_pb.SubjectCondition
	GetAlgorithms() []string
}

// UpdateRequest is implemented by UpdateWorkloadIdentityFederationRequest of
// both zitadel.application.v2 and zitadel.user.v2.
type UpdateRequest interface {
	CreateRequest
	GetId() string
	GetState() wif_pb.WorkloadIdentityState
}

// WorkloadIdentityCreateRequestToModel maps an Add request onto the command
// model. The owner (OwnerType/OwnerID/ProjectID/PermissionCheck) is wired by
// the calling service; created configurations are always active.
func WorkloadIdentityCreateRequestToModel(req CreateRequest) (*command.WorkloadIdentity, error) {
	subjectConditions, err := SubjectConditionsToDomain(req.GetSubjectConditions())
	if err != nil {
		return nil, err
	}
	return &command.WorkloadIdentity{
		Name:              req.GetName(),
		Issuer:            req.GetIssuer(),
		JwksURI:           req.GetJwksUri(),
		Audiences:         req.GetAudiences(),
		SubjectConditions: subjectConditions,
		Algorithms:        req.GetAlgorithms(),
		State:             domain.WorkloadIdentityStateActive,
	}, nil
}

// WorkloadIdentityUpdateRequestToModel maps an Update request (full desired
// state) onto the command model, keyed by the configuration ID.
func WorkloadIdentityUpdateRequestToModel(req UpdateRequest) (*command.WorkloadIdentity, error) {
	subjectConditions, err := SubjectConditionsToDomain(req.GetSubjectConditions())
	if err != nil {
		return nil, err
	}
	state, err := WorkloadIdentityStateToDomain(req.GetState())
	if err != nil {
		return nil, err
	}
	return &command.WorkloadIdentity{
		ObjectRoot:        models.ObjectRoot{AggregateID: req.GetId()},
		Name:              req.GetName(),
		Issuer:            req.GetIssuer(),
		JwksURI:           req.GetJwksUri(),
		Audiences:         req.GetAudiences(),
		SubjectConditions: subjectConditions,
		Algorithms:        req.GetAlgorithms(),
		State:             state,
	}, nil
}

// WorkloadIdentityToPb maps a projected configuration onto the API message.
func WorkloadIdentityToPb(identity *query.WorkloadIdentity) *wif_pb.WorkloadIdentityFederationConfig {
	return &wif_pb.WorkloadIdentityFederationConfig{
		Id:                identity.ID,
		Name:              identity.Name,
		Issuer:            identity.Issuer,
		JwksUri:           identity.JwksURI,
		Audiences:         identity.Audiences,
		SubjectConditions: SubjectConditionsToPb(identity.SubjectConditions),
		Algorithms:        identity.Algorithms,
		State:             WorkloadIdentityStateToPb(identity.State),
		CreationDate:      timestamppb.New(identity.CreationDate),
		ChangeDate:        timestamppb.New(identity.ChangeDate),
	}
}

// WorkloadIdentitiesToPb maps a list of projected configurations.
func WorkloadIdentitiesToPb(identities []*query.WorkloadIdentity) []*wif_pb.WorkloadIdentityFederationConfig {
	result := make([]*wif_pb.WorkloadIdentityFederationConfig, len(identities))
	for i, identity := range identities {
		result[i] = WorkloadIdentityToPb(identity)
	}
	return result
}

// SubjectConditionsToDomain maps the oneof conditions onto their domain
// representation, rejecting requests that omit the condition.
func SubjectConditionsToDomain(conditions []*wif_pb.SubjectCondition) ([]domain.SubjectCondition, error) {
	result := make([]domain.SubjectCondition, len(conditions))
	for i, condition := range conditions {
		switch c := condition.GetCondition().(type) {
		case *wif_pb.SubjectCondition_Exact:
			result[i] = domain.SubjectCondition{MatchType: domain.SubjectMatchTypeExact, Value: c.Exact}
		case *wif_pb.SubjectCondition_Prefix:
			result[i] = domain.SubjectCondition{MatchType: domain.SubjectMatchTypePrefix, Value: c.Prefix}
		case *wif_pb.SubjectCondition_Regex:
			result[i] = domain.SubjectCondition{MatchType: domain.SubjectMatchTypeRegex, Value: c.Regex}
		default:
			return nil, zerrors.ThrowInvalidArgument(nil, "GRPC-wif1", "Errors.WorkloadIdentity.SubjectConditionRequired")
		}
	}
	return result, nil
}

// SubjectConditionsToPb maps domain conditions back onto the oneof messages.
func SubjectConditionsToPb(conditions []domain.SubjectCondition) []*wif_pb.SubjectCondition {
	result := make([]*wif_pb.SubjectCondition, len(conditions))
	for i, condition := range conditions {
		switch condition.MatchType {
		case domain.SubjectMatchTypePrefix:
			result[i] = &wif_pb.SubjectCondition{Condition: &wif_pb.SubjectCondition_Prefix{Prefix: condition.Value}}
		case domain.SubjectMatchTypeRegex:
			result[i] = &wif_pb.SubjectCondition{Condition: &wif_pb.SubjectCondition_Regex{Regex: condition.Value}}
		default:
			result[i] = &wif_pb.SubjectCondition{Condition: &wif_pb.SubjectCondition_Exact{Exact: condition.Value}}
		}
	}
	return result
}

// WorkloadIdentityStateToDomain maps the API state enum, refusing the
// unspecified value which only exists as a write model marker.
func WorkloadIdentityStateToDomain(state wif_pb.WorkloadIdentityState) (domain.WorkloadIdentityState, error) {
	switch state {
	case wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_ACTIVE:
		return domain.WorkloadIdentityStateActive, nil
	case wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_INACTIVE:
		return domain.WorkloadIdentityStateInactive, nil
	default:
		return domain.WorkloadIdentityStateUnspecified, zerrors.ThrowInvalidArgument(nil, "GRPC-wif2", "Errors.WorkloadIdentity.StateInvalid")
	}
}

// WorkloadIdentityStateToPb maps the domain state onto the API enum.
func WorkloadIdentityStateToPb(state domain.WorkloadIdentityState) wif_pb.WorkloadIdentityState {
	switch state {
	case domain.WorkloadIdentityStateActive:
		return wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_ACTIVE
	case domain.WorkloadIdentityStateInactive:
		return wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_INACTIVE
	default:
		return wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_UNSPECIFIED
	}
}
