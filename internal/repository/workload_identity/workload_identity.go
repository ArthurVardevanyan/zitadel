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
	return NewAddUniqueConstraints(e.OwnerType, e.OwnerID, e.Issuer, e.SubjectConditions)
}

func NewWorkloadIdentityAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
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
// so reducers never need to track partial changes. Previous is only used to
// release unique constraints of the replaced state.
type WorkloadIdentityChangedEvent struct {
	eventstore.BaseEvent `json:"-"`

	Previous          *WorkloadIdentityAddedEvent      `json:"previous,omitempty"`
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

func (e *WorkloadIdentityChangedEvent) Payload() interface{} {
	return e
}

func (e *WorkloadIdentityChangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	var constraints []*eventstore.UniqueConstraint
	if e.Previous != nil {
		constraints = NewRemoveUniqueConstraints(e.Previous.OwnerType, e.Previous.OwnerID, e.Previous.Issuer, e.Previous.SubjectConditions)
	}
	return append(constraints, NewAddUniqueConstraints(e.OwnerType, e.OwnerID, e.Issuer, e.SubjectConditions)...)
}

func NewWorkloadIdentityChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	previous *WorkloadIdentityAddedEvent,
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
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			WorkloadIdentityChangedEventType,
		),
		Previous:          previous,
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

func WorkloadIdentityChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &WorkloadIdentityChangedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	err := event.Unmarshal(e)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "WLDID-4pLq8", "unable to unmarshal workload identity changed")
	}
	return e, nil
}

// WorkloadIdentityRemovedEvent deletes the configuration. It keeps the fields
// needed to release the unique constraints of the removed state.
type WorkloadIdentityRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`

	OwnerType         domain.WorkloadIdentityOwnerType `json:"ownerType"`
	OwnerID           string                           `json:"ownerId"`
	Issuer            string                           `json:"issuer"`
	SubjectConditions []domain.SubjectCondition        `json:"subjectConditions"`
}

func (e *WorkloadIdentityRemovedEvent) Payload() interface{} {
	return e
}

func (e *WorkloadIdentityRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return NewRemoveUniqueConstraints(e.OwnerType, e.OwnerID, e.Issuer, e.SubjectConditions)
}

func NewWorkloadIdentityRemovedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	ownerType domain.WorkloadIdentityOwnerType,
	ownerID string,
	issuer string,
	subjectConditions []domain.SubjectCondition,
) *WorkloadIdentityRemovedEvent {
	return &WorkloadIdentityRemovedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			WorkloadIdentityRemovedEventType,
		),
		OwnerType:         ownerType,
		OwnerID:           ownerID,
		Issuer:            issuer,
		SubjectConditions: subjectConditions,
	}
}

func WorkloadIdentityRemovedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &WorkloadIdentityRemovedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	err := event.Unmarshal(e)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "WLDID-2xDs5", "unable to unmarshal workload identity removed")
	}
	return e, nil
}
