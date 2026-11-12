package command

import (
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	wif_repo "github.com/zitadel/zitadel/internal/repository/workload_identity"
)

type WorkloadIdentityWriteModel struct {
	eventstore.WriteModel

	ConfigID          string
	OwnerType         domain.WorkloadIdentityOwnerType
	OwnerID           string
	Name              string
	Issuer            string
	JwksURI           string
	Audiences         []string
	SubjectConditions []domain.SubjectCondition
	Algorithms        []string

	State   domain.WorkloadIdentityState
	removed bool
}

func NewWorkloadIdentityWriteModel(configID, resourceOwner string) *WorkloadIdentityWriteModel {
	return &WorkloadIdentityWriteModel{
		WriteModel: eventstore.WriteModel{
			AggregateID:   configID,
			ResourceOwner: resourceOwner,
		},
		ConfigID: configID,
	}
}

func (wm *WorkloadIdentityWriteModel) Reduce() error {
	for _, event := range wm.Events {
		switch e := event.(type) {
		case *wif_repo.WorkloadIdentityAddedEvent:
			wm.reduceState(e.OwnerType, e.OwnerID, e.Name, e.Issuer, e.JwksURI, e.Audiences, e.SubjectConditions, e.Algorithms, e.State)
		case *wif_repo.WorkloadIdentityChangedEvent:
			wm.reduceState(e.OwnerType, e.OwnerID, e.Name, e.Issuer, e.JwksURI, e.Audiences, e.SubjectConditions, e.Algorithms, e.State)
		case *wif_repo.WorkloadIdentityRemovedEvent:
			wm.removed = true
			wm.State = domain.WorkloadIdentityStateUnspecified
		}
	}
	return wm.WriteModel.Reduce()
}

func (wm *WorkloadIdentityWriteModel) reduceState(
	ownerType domain.WorkloadIdentityOwnerType,
	ownerID, name, issuer, jwksURI string,
	audiences []string,
	subjectConditions []domain.SubjectCondition,
	algorithms []string,
	state domain.WorkloadIdentityState,
) {
	wm.OwnerType = ownerType
	wm.OwnerID = ownerID
	wm.Name = name
	wm.Issuer = issuer
	wm.JwksURI = jwksURI
	wm.Audiences = audiences
	wm.SubjectConditions = subjectConditions
	wm.Algorithms = algorithms
	wm.State = state
	wm.removed = false
}

func (wm *WorkloadIdentityWriteModel) Query() *eventstore.SearchQueryBuilder {
	return eventstore.NewSearchQueryBuilder(eventstore.ColumnsEvent).
		ResourceOwner(wm.ResourceOwner).
		AddQuery().
		AggregateTypes(wif_repo.AggregateType).
		AggregateIDs(wm.AggregateID).
		EventTypes(
			wif_repo.WorkloadIdentityAddedEventType,
			wif_repo.WorkloadIdentityChangedEventType,
			wif_repo.WorkloadIdentityRemovedEventType,
		).
		Builder()
}

func (wm *WorkloadIdentityWriteModel) Exists() bool {
	return !wm.removed && wm.State != domain.WorkloadIdentityStateUnspecified
}

// currentAsAdded reconstructs the payload of the reduced state so it can be
// embedded as previous state in a changed event, or trimmed into a removed
// event, without re-querying the eventstore.
func (wm *WorkloadIdentityWriteModel) currentAsAdded() *wif_repo.WorkloadIdentityAddedEvent {
	return &wif_repo.WorkloadIdentityAddedEvent{
		OwnerType:         wm.OwnerType,
		OwnerID:           wm.OwnerID,
		Name:              wm.Name,
		Issuer:            wm.Issuer,
		JwksURI:           wm.JwksURI,
		Audiences:         wm.Audiences,
		SubjectConditions: wm.SubjectConditions,
		Algorithms:        wm.Algorithms,
		State:             wm.State,
	}
}

func WorkloadIdentityAggregateFromWriteModel(wm *eventstore.WriteModel) *eventstore.Aggregate {
	return eventstore.AggregateFromWriteModel(wm, wif_repo.AggregateType, wif_repo.AggregateVersion)
}
