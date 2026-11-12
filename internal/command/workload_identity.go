package command

import (
	"context"
	"slices"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	wif_repo "github.com/zitadel/zitadel/internal/repository/workload_identity"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// WorkloadIdentity is the command model of a workload identity federation
// configuration. AggregateID is the configuration ID (new per rule), the owner
// (application or service user) is referenced by OwnerType/OwnerID.
type WorkloadIdentity struct {
	models.ObjectRoot

	// ProjectID is required for application owned configurations, it locates
	// the project aggregate which carries the application events.
	ProjectID string
	// PermissionCheck is required for service user owned configurations.
	PermissionCheck PermissionCheck

	OwnerType         domain.WorkloadIdentityOwnerType
	OwnerID           string
	Name              string
	Issuer            string
	JwksURI           string
	Audiences         []string
	SubjectConditions []domain.SubjectCondition
	Algorithms        []string
	State             domain.WorkloadIdentityState
}

func (wif *WorkloadIdentity) toDomain() *domain.WorkloadIdentityFederation {
	return &domain.WorkloadIdentityFederation{
		ObjectRoot:        wif.ObjectRoot,
		OwnerType:         wif.OwnerType,
		OwnerID:           wif.OwnerID,
		Name:              wif.Name,
		Issuer:            wif.Issuer,
		JwksURI:           wif.JwksURI,
		Audiences:         wif.Audiences,
		SubjectConditions: wif.SubjectConditions,
		Algorithms:        wif.Algorithms,
		State:             wif.State,
	}
}

// checkWorkloadIdentityOwner verifies the owner of the configuration exists
// and the caller is allowed to manage workload identity federations on it.
// It returns the resource owner of the owner.
func (c *Commands) checkWorkloadIdentityOwner(ctx context.Context, wif *WorkloadIdentity) (string, error) {
	switch wif.OwnerType {
	case domain.WorkloadIdentityOwnerTypeApp:
		if wif.ProjectID == "" {
			return "", zerrors.ThrowInvalidArgument(nil, "WIDCO-f2nQ4", "Errors.Invalid.Argument")
		}
		projectResourceOwner, err := c.checkProjectExists(ctx, wif.ProjectID, wif.ResourceOwner)
		if err != nil {
			return "", err
		}
		appWM := NewApplicationWriteModelWithAppIDC(wif.ProjectID, wif.OwnerID, projectResourceOwner)
		if err := c.eventstore.FilterToQueryReducer(ctx, appWM); err != nil {
			return "", err
		}
		if appWM.State != domain.AppStateActive {
			return "", zerrors.ThrowNotFound(nil, "WIDCO-8VkT2", "Errors.Project.App.NotExisting")
		}
		if err := c.checkPermissionUpdateApplication(ctx, appWM.ResourceOwner, wif.ProjectID); err != nil {
			return "", err
		}
		return appWM.ResourceOwner, nil
	case domain.WorkloadIdentityOwnerTypeServiceUser:
		userResourceOwner, exists, err := existingUser(ctx, c.eventstore.Filter, wif.OwnerID, wif.ResourceOwner, true)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", zerrors.ThrowPreconditionFailed(nil, "WIDCO-sN9d5", "Errors.User.NotFound")
		}
		if wif.PermissionCheck == nil {
			return "", zerrors.ThrowPermissionDenied(nil, "WIDCO-gH2v7", "Errors.PermissionDenied")
		}
		if err := wif.PermissionCheck(userResourceOwner, wif.OwnerID); err != nil {
			return "", err
		}
		return userResourceOwner, nil
	default:
		return "", zerrors.ThrowInvalidArgument(nil, "WIDCO-p5Rj9", "Errors.Invalid.Argument")
	}
}

func (c *Commands) AddWorkloadIdentityFederation(ctx context.Context, wif *WorkloadIdentity) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if err := wif.toDomain().IsValid(); err != nil {
		return nil, err
	}
	resourceOwner, err := c.checkWorkloadIdentityOwner(ctx, wif)
	if err != nil {
		return nil, err
	}
	if wif.AggregateID == "" {
		configID, err := c.idGenerator.Next()
		if err != nil {
			return nil, err
		}
		wif.AggregateID = configID
	}

	writeModel := NewWorkloadIdentityWriteModel(wif.AggregateID, resourceOwner)
	if err := c.eventstore.FilterToQueryReducer(ctx, writeModel); err != nil {
		return nil, err
	}
	if writeModel.Exists() {
		return nil, zerrors.ThrowAlreadyExists(nil, "WIDCO-mT8x3", "Errors.WorkloadIdentity.AlreadyExists")
	}

	pushedEvents, err := c.eventstore.Push(ctx, wif_repo.NewWorkloadIdentityAddedEvent(
		ctx,
		WorkloadIdentityAggregateFromWriteModel(&writeModel.WriteModel),
		wif.OwnerType,
		wif.OwnerID,
		wif.Name,
		wif.Issuer,
		wif.JwksURI,
		wif.Audiences,
		wif.SubjectConditions,
		wif.Algorithms,
		wif.State,
	))
	if err != nil {
		return nil, err
	}
	return pushedEventsDetails(pushedEvents), nil
}

// UpdateWorkloadIdentityFederation stores the provided (already merged) full
// desired state of the configuration. The owner binding cannot be changed.
func (c *Commands) UpdateWorkloadIdentityFederation(ctx context.Context, wif *WorkloadIdentity) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if wif.AggregateID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "WIDCU-k3Lp8", "Errors.IDMissing")
	}
	if err := wif.toDomain().IsValid(); err != nil {
		return nil, err
	}

	writeModel := NewWorkloadIdentityWriteModel(wif.AggregateID, wif.ResourceOwner)
	if err := c.eventstore.FilterToQueryReducer(ctx, writeModel); err != nil {
		return nil, err
	}
	if !writeModel.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "WIDCU-v6Bn2", "Errors.WorkloadIdentity.NotFound")
	}
	if writeModel.OwnerType != wif.OwnerType || writeModel.OwnerID != wif.OwnerID {
		return nil, zerrors.ThrowInvalidArgument(nil, "WIDCU-z4Qw6", "Errors.WorkloadIdentity.OwnerMismatch")
	}
	// re-check management permission on the (existing) owner
	if _, err := c.checkWorkloadIdentityOwner(ctx, &WorkloadIdentity{
		ObjectRoot:      models.ObjectRoot{ResourceOwner: writeModel.ResourceOwner},
		ProjectID:       wif.ProjectID,
		PermissionCheck: wif.PermissionCheck,
		OwnerType:       wif.OwnerType,
		OwnerID:         wif.OwnerID,
	}); err != nil {
		return nil, err
	}

	if workloadIdentityStateEqual(writeModel, wif) {
		return nil, zerrors.ThrowPreconditionFailed(nil, "WIDCU-t7Yd4", "Errors.NoChangesFound")
	}

	pushedEvents, err := c.eventstore.Push(ctx, wif_repo.NewWorkloadIdentityChangedEvent(
		ctx,
		WorkloadIdentityAggregateFromWriteModel(&writeModel.WriteModel),
		writeModel.currentAsAdded(),
		wif.OwnerType,
		wif.OwnerID,
		wif.Name,
		wif.Issuer,
		wif.JwksURI,
		wif.Audiences,
		wif.SubjectConditions,
		wif.Algorithms,
		wif.State,
	))
	if err != nil {
		return nil, err
	}
	return pushedEventsDetails(pushedEvents), nil
}

func (c *Commands) RemoveWorkloadIdentityFederation(ctx context.Context, wif *WorkloadIdentity) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if wif.AggregateID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "WIDCR-b9Km1", "Errors.IDMissing")
	}

	writeModel := NewWorkloadIdentityWriteModel(wif.AggregateID, wif.ResourceOwner)
	if err := c.eventstore.FilterToQueryReducer(ctx, writeModel); err != nil {
		return nil, err
	}
	if !writeModel.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "WIDCR-n2Fj7", "Errors.WorkloadIdentity.NotFound")
	}
	if _, err := c.checkWorkloadIdentityOwner(ctx, &WorkloadIdentity{
		ObjectRoot:      models.ObjectRoot{ResourceOwner: writeModel.ResourceOwner},
		ProjectID:       wif.ProjectID,
		PermissionCheck: wif.PermissionCheck,
		OwnerType:       writeModel.OwnerType,
		OwnerID:         writeModel.OwnerID,
	}); err != nil {
		return nil, err
	}

	previous := writeModel.currentAsAdded()
	pushedEvents, err := c.eventstore.Push(ctx, wif_repo.NewWorkloadIdentityRemovedEvent(
		ctx,
		WorkloadIdentityAggregateFromWriteModel(&writeModel.WriteModel),
		previous.OwnerType,
		previous.OwnerID,
		previous.Issuer,
		previous.SubjectConditions,
	))
	if err != nil {
		return nil, err
	}
	return pushedEventsDetails(pushedEvents), nil
}

func workloadIdentityStateEqual(wm *WorkloadIdentityWriteModel, wif *WorkloadIdentity) bool {
	return wm.OwnerType == wif.OwnerType &&
		wm.OwnerID == wif.OwnerID &&
		wm.Name == wif.Name &&
		wm.Issuer == wif.Issuer &&
		wm.JwksURI == wif.JwksURI &&
		slices.Equal(wm.Audiences, wif.Audiences) &&
		slices.Equal(wm.SubjectConditions, wif.SubjectConditions) &&
		slices.Equal(wm.Algorithms, wif.Algorithms) &&
		wm.State == wif.State
}

func pushedEventsDetails(events []eventstore.Event) *domain.ObjectDetails {
	return &domain.ObjectDetails{
		Sequence:      events[len(events)-1].Sequence(),
		EventDate:     events[len(events)-1].CreatedAt(),
		ResourceOwner: events[len(events)-1].Aggregate().ResourceOwner,
	}
}
