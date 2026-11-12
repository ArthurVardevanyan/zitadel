package workload_identity

import (
	"context"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const (
	eventPrefix                      = "federation."
	WorkloadIdentityAddedEventType   = eventPrefix + "added"
	WorkloadIdentityChangedEventType = eventPrefix + "changed"
	WorkloadIdentityRemovedEventType = eventPrefix + "removed"
)

// WorkloadIdentityAddedEvent is pushed when a new workload identity federation
// configuration is added to an application or service user.
type WorkloadIdentityAddedEvent struct {
	eventstore.BaseEvent `json:"-"`

	InstanceID        string                           `json:"instanceId,omitempty"`
	OwnerType         domain.WorkloadIdentityOwnerType `json:"ownerType"`
	OwnerID           string                           `json:"ownerId"`
	Name              string                           `json:"name,omitempty"`
	Issuer            string                           `json:"issuer"`
	JwksURI           string                           `json:"jwksUri,omitempty"`
	Audiences         []string                         `json:"audiences"`
	SubjectConditions []domain.SubjectCondition        `json:"subjectConditions"`
	Algorithms        []string                         `json:"algorithms,omitempty"`
	State             domain.WorkloadIdentityState     `json:"state"`
}

func (e *WorkloadIdentityAddedEvent) Payload() interface{} {
	return e
}

func (e *WorkloadIdentityAddedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewWorkloadIdentityAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	instanceID string,
	ownerType domain.WorkloadIdentityOwnerType,
	ownerID string,
	name string,
	issuer string,
	jwksURI string,
	audiences []string,
	subjectConditions []domain.SubjectCondition,
	algorithms []string,
	state domain.WorkloadIdentityState,
) *WorkloadIdentityAddedEvent {
	return &WorkloadIdentityAddedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			WorkloadIdentityAddedEventType,
		),
		InstanceID:        instanceID,
		OwnerType:         ownerType,
		OwnerID:           ownerID,
		Name:              name,
		Issuer:            issuer,
		JwksURI:           jwksURI,
		Audiences:         audiences,
		SubjectConditions: subjectConditions,
		Algorithms:        algorithms,
		State:             state,
	}
}

func WorkloadIdentityAddedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &WorkloadIdentityAddedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	err := event.Unmarshal(e)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "WLDID-7mkP2", "unable to unmarshal workload identity added")
	}
	return e, nil
}

// WorkloadIdentityChangedEvent carries the full new state of the configuration.
// The command layer merges update fields into the previous state before push,
// so reducers never need to track partial changes.
type WorkloadIdentityChangedEvent struct {
	WorkloadIdentityAddedEvent `json:"-"`
}

func (e *WorkloadIdentityChangedEvent) Payload() interface{} {
	return &e.WorkloadIdentityAddedEvent
}

func (e *WorkloadIdentityChangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewWorkloadIdentityChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	instanceID string,
	ownerType domain.WorkloadIdentityOwnerType,
	ownerID string,
	name string,
	issuer string,
	jwksURI string,
	audiences []string,
	subjectConditions []domain.SubjectCondition,
	algorithms []string,
	state domain.WorkloadIdentityState,
) *WorkloadIdentityChangedEvent {
	return &WorkloadIdentityChangedEvent{
		WorkloadIdentityAddedEvent: WorkloadIdentityAddedEvent{
			BaseEvent: *eventstore.NewBaseEventForPush(
				ctx,
				aggregate,
				WorkloadIdentityChangedEventType,
			),
			InstanceID:        instanceID,
			OwnerType:         ownerType,
			OwnerID:           ownerID,
			Name:              name,
			Issuer:            issuer,
			JwksURI:           jwksURI,
			Audiences:         audiences,
			SubjectConditions: subjectConditions,
			Algorithms:        algorithms,
			State:             state,
		},
	}
}

func WorkloadIdentityChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	added := &WorkloadIdentityAddedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	err := event.Unmarshal(added)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "WLDID-4pLq8", "unable to unmarshal workload identity changed")
	}
	return &WorkloadIdentityChangedEvent{WorkloadIdentityAddedEvent: *added}, nil
}

// WorkloadIdentityRemovedEvent deletes the configuration.
type WorkloadIdentityRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`
}

func (e *WorkloadIdentityRemovedEvent) Payload() interface{} {
	return nil
}

func (e *WorkloadIdentityRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewWorkloadIdentityRemovedEvent(ctx context.Context, aggregate *eventstore.Aggregate) *WorkloadIdentityRemovedEvent {
	return &WorkloadIdentityRemovedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			WorkloadIdentityRemovedEventType,
		),
	}
}

func WorkloadIdentityRemovedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	return &WorkloadIdentityRemovedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}, nil
}
