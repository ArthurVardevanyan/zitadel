package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/domain"
	application_pb "github.com/zitadel/zitadel/pkg/grpc/application/v2"
	user_pb "github.com/zitadel/zitadel/pkg/grpc/user/v2"
	wif_pb "github.com/zitadel/zitadel/pkg/grpc/workload_identity/v2"
)

func TestSubjectConditionsToDomain(t *testing.T) {
	conditions, err := SubjectConditionsToDomain([]*wif_pb.SubjectCondition{
		{Condition: &wif_pb.SubjectCondition_Exact{Exact: "repo:owner/name"}},
		{Condition: &wif_pb.SubjectCondition_Prefix{Prefix: "repo:owner/"}},
		{Condition: &wif_pb.SubjectCondition_Regex{Regex: `repo:owner/.*`}},
	})
	require.NoError(t, err)
	assert.Equal(t, []domain.SubjectCondition{
		{MatchType: domain.SubjectMatchTypeExact, Value: "repo:owner/name"},
		{MatchType: domain.SubjectMatchTypePrefix, Value: "repo:owner/"},
		{MatchType: domain.SubjectMatchTypeRegex, Value: `repo:owner/.*`},
	}, conditions)

	// round trip
	back := SubjectConditionsToPb(conditions)
	roundTripped, err := SubjectConditionsToDomain(back)
	require.NoError(t, err)
	assert.Equal(t, conditions, roundTripped)
}

func TestSubjectConditionsToDomainEmptyOneof(t *testing.T) {
	_, err := SubjectConditionsToDomain([]*wif_pb.SubjectCondition{{}})
	require.Error(t, err)
}

func TestWorkloadIdentityStateToDomain(t *testing.T) {
	state, err := WorkloadIdentityStateToDomain(wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_ACTIVE)
	require.NoError(t, err)
	assert.Equal(t, domain.WorkloadIdentityStateActive, state)

	state, err = WorkloadIdentityStateToDomain(wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_INACTIVE)
	require.NoError(t, err)
	assert.Equal(t, domain.WorkloadIdentityStateInactive, state)

	_, err = WorkloadIdentityStateToDomain(wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_UNSPECIFIED)
	require.Error(t, err)

	assert.Equal(t, wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_ACTIVE, WorkloadIdentityStateToPb(domain.WorkloadIdentityStateActive))
	assert.Equal(t, wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_INACTIVE, WorkloadIdentityStateToPb(domain.WorkloadIdentityStateInactive))
	assert.Equal(t, wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_UNSPECIFIED, WorkloadIdentityStateToPb(domain.WorkloadIdentityStateUnspecified))
}

func TestWorkloadIdentityCreateRequestToModel(t *testing.T) {
	// the request types of both services must satisfy the converter interfaces
	var req CreateRequest = &application_pb.AddApplicationWorkloadIdentityFederationRequest{
		Name:      "github-actions",
		Issuer:    "https://token.actions.githubusercontent.com",
		JwksUri:   "https://token.actions.githubusercontent.com/keys",
		Audiences: []string{"https://zitadel.example.com"},
		SubjectConditions: []*wif_pb.SubjectCondition{
			{Condition: &wif_pb.SubjectCondition_Prefix{Prefix: "repo:ArthurVardevanyan/"}},
		},
		Algorithms: []string{"RS256"},
	}
	model, err := WorkloadIdentityCreateRequestToModel(req)
	require.NoError(t, err)
	assert.Equal(t, "github-actions", model.Name)
	assert.Equal(t, "https://token.actions.githubusercontent.com", model.Issuer)
	assert.Equal(t, "https://token.actions.githubusercontent.com/keys", model.JwksURI)
	assert.Equal(t, []string{"https://zitadel.example.com"}, model.Audiences)
	assert.Equal(t, []string{"RS256"}, model.Algorithms)
	assert.Equal(t, []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypePrefix, Value: "repo:ArthurVardevanyan/"}}, model.SubjectConditions)
	// created configurations are always active
	assert.Equal(t, domain.WorkloadIdentityStateActive, model.State)

	var upd UpdateRequest = &user_pb.UpdateWorkloadIdentityFederationRequest{
		Id:                "configID",
		Name:              "renamed",
		Issuer:            "https://oidc.example.com",
		Audiences:         []string{"zitadel"},
		SubjectConditions: []*wif_pb.SubjectCondition{{Condition: &wif_pb.SubjectCondition_Exact{Exact: "sub"}}},
		State:             wif_pb.WorkloadIdentityState_WORKLOAD_IDENTITY_STATE_INACTIVE,
	}
	model, err = WorkloadIdentityUpdateRequestToModel(upd)
	require.NoError(t, err)
	assert.Equal(t, "configID", model.AggregateID)
	assert.Equal(t, "renamed", model.Name)
	assert.Equal(t, domain.WorkloadIdentityStateInactive, model.State)
}

func TestWorkloadIdentityUpdateRequestToModelInvalidState(t *testing.T) {
	req := &application_pb.UpdateApplicationWorkloadIdentityFederationRequest{
		Id:                "configID",
		Name:              "stateless",
		Issuer:            "https://oidc.example.com",
		Audiences:         []string{"zitadel"},
		SubjectConditions: []*wif_pb.SubjectCondition{{Condition: &wif_pb.SubjectCondition_Exact{Exact: "sub"}}},
	}
	_, err := WorkloadIdentityUpdateRequestToModel(req)
	require.Error(t, err)
}
