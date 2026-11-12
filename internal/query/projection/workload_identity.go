package projection

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	old_handler "github.com/zitadel/zitadel/internal/eventstore/handler"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/repository/user"
	wif_repo "github.com/zitadel/zitadel/internal/repository/workload_identity"
)

const (
	WorkloadIdentityTable            = "projections.workload_identities1"
	WorkloadIdentityIDCol            = "id"
	WorkloadIdentityCreationDateCol  = "creation_date"
	WorkloadIdentityChangeDateCol    = "change_date"
	WorkloadIdentityResourceOwnerCol = "resource_owner"
	WorkloadIdentityInstanceIDCol    = "instance_id"
	WorkloadIdentitySequenceCol      = "sequence"
	WorkloadIdentityOwnerTypeCol     = "owner_type"
	WorkloadIdentityOwnerIDCol       = "owner_id"
	WorkloadIdentityNameCol          = "name"
	WorkloadIdentityIssuerCol        = "issuer"
	WorkloadIdentityJwksURICol       = "jwks_uri"
	WorkloadIdentityAudiencesCol     = "audiences"
	WorkloadIdentitySubjectCondsCol  = "subject_conditions"
	WorkloadIdentityAlgorithmsCol    = "algorithms"
	WorkloadIdentityStateCol         = "state"
)

type workloadIdentityProjection struct{}

func newWorkloadIdentityProjection(ctx context.Context, config handler.Config) *handler.Handler {
	return handler.NewHandler(ctx, &config, new(workloadIdentityProjection))
}

func (*workloadIdentityProjection) Name() string {
	return WorkloadIdentityTable
}

func (*workloadIdentityProjection) Init() *old_handler.Check {
	return handler.NewTableCheck(
		handler.NewTable([]*handler.InitColumn{
			handler.NewColumn(WorkloadIdentityIDCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentityCreationDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(WorkloadIdentityChangeDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(WorkloadIdentityResourceOwnerCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentityInstanceIDCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentitySequenceCol, handler.ColumnTypeInt64),
			handler.NewColumn(WorkloadIdentityOwnerTypeCol, handler.ColumnTypeEnum, handler.Default(0)),
			handler.NewColumn(WorkloadIdentityOwnerIDCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentityNameCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentityIssuerCol, handler.ColumnTypeText),
			handler.NewColumn(WorkloadIdentityJwksURICol, handler.ColumnTypeText, handler.Nullable()),
			handler.NewColumn(WorkloadIdentityAudiencesCol, handler.ColumnTypeTextArray),
			handler.NewColumn(WorkloadIdentitySubjectCondsCol, handler.ColumnTypeJSONB),
			handler.NewColumn(WorkloadIdentityAlgorithmsCol, handler.ColumnTypeTextArray, handler.Nullable()),
			handler.NewColumn(WorkloadIdentityStateCol, handler.ColumnTypeEnum, handler.Default(0)),
		},
			handler.NewPrimaryKey(WorkloadIdentityInstanceIDCol, WorkloadIdentityIDCol),
			handler.WithIndex(handler.NewIndex("owner_id", []string{WorkloadIdentityOwnerIDCol})),
			handler.WithIndex(handler.NewIndex("issuer", []string{WorkloadIdentityIssuerCol})),
			handler.WithIndex(handler.NewIndex("resource_owner", []string{WorkloadIdentityResourceOwnerCol})),
		),
	)
}

func (p *workloadIdentityProjection) Reducers() []handler.AggregateReducer {
	return []handler.AggregateReducer{
		{
			Aggregate: wif_repo.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  wif_repo.WorkloadIdentityAddedEventType,
					Reduce: p.reduceAdded,
				},
				{
					Event:  wif_repo.WorkloadIdentityChangedEventType,
					Reduce: p.reduceChanged,
				},
				{
					Event:  wif_repo.WorkloadIdentityRemovedEventType,
					Reduce: p.reduceRemoved,
				},
			},
		},
		{
			// Owner cascade deletes. Configurations of removed projects stay
			// inert: they are never resolvable (the client/user lookup fails
			// first at authentication time) and never listed (owner-scoped
			// management queries).
			Aggregate: user.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  user.UserRemovedType,
					Reduce: p.reduceServiceUserRemoved,
				},
			},
		},
		{
			Aggregate: project.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  project.ApplicationRemovedType,
					Reduce: p.reduceApplicationRemoved,
				},
			},
		},
		{
			Aggregate: org.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  org.OrgRemovedEventType,
					Reduce: p.reduceOwnerRemoved,
				},
			},
		},
		{
			Aggregate: instance.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  instance.InstanceRemovedEventType,
					Reduce: reduceInstanceRemovedHelper(WorkloadIdentityInstanceIDCol),
				},
			},
		},
	}
}

func (p *workloadIdentityProjection) reduceAdded(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*wif_repo.WorkloadIdentityAddedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewCreateStatement(
		e,
		workloadIdentityCreateColumns(e.Aggregate(), workloadIdentityRow{
			OwnerType:         e.OwnerType,
			OwnerID:           e.OwnerID,
			Name:              e.Name,
			Issuer:            e.Issuer,
			JwksURI:           e.JwksURI,
			Audiences:         e.Audiences,
			SubjectConditions: e.SubjectConditions,
			Algorithms:        e.Algorithms,
			State:             e.State,
		}, e.CreationDate(), e.Sequence()),
	), nil
}

func (p *workloadIdentityProjection) reduceChanged(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*wif_repo.WorkloadIdentityChangedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewUpdateStatement(
		e,
		[]handler.Column{
			handler.NewCol(WorkloadIdentityChangeDateCol, e.CreationDate()),
			handler.NewCol(WorkloadIdentityOwnerTypeCol, e.OwnerType),
			handler.NewCol(WorkloadIdentityOwnerIDCol, e.OwnerID),
			handler.NewCol(WorkloadIdentityNameCol, e.Name),
			handler.NewCol(WorkloadIdentityIssuerCol, e.Issuer),
			handler.NewCol(WorkloadIdentityJwksURICol, e.JwksURI),
			handler.NewCol(WorkloadIdentityAudiencesCol, database.TextArray[string](e.Audiences)),
			handler.NewCol(WorkloadIdentitySubjectCondsCol, marshalSubjectConditions(e.SubjectConditions)),
			handler.NewCol(WorkloadIdentityAlgorithmsCol, database.TextArray[string](e.Algorithms)),
			handler.NewCol(WorkloadIdentityStateCol, e.State),
			handler.NewCol(WorkloadIdentitySequenceCol, e.Sequence()),
		},
		[]handler.Condition{
			handler.NewCond(WorkloadIdentityInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(WorkloadIdentityIDCol, e.Aggregate().ID),
		},
	), nil
}

func (p *workloadIdentityProjection) reduceRemoved(event eventstore.Event) (*handler.Statement, error) {
	_, err := assertEvent[*wif_repo.WorkloadIdentityRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		event,
		[]handler.Condition{
			handler.NewCond(WorkloadIdentityInstanceIDCol, event.Aggregate().InstanceID),
			handler.NewCond(WorkloadIdentityIDCol, event.Aggregate().ID),
		},
	), nil
}

func (p *workloadIdentityProjection) reduceServiceUserRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*user.UserRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(WorkloadIdentityInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(WorkloadIdentityOwnerIDCol, e.Aggregate().ID),
			handler.NewCond(WorkloadIdentityOwnerTypeCol, domain.WorkloadIdentityOwnerTypeServiceUser),
		},
	), nil
}

func (p *workloadIdentityProjection) reduceApplicationRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*project.ApplicationRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(WorkloadIdentityInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(WorkloadIdentityOwnerIDCol, e.AppID),
			handler.NewCond(WorkloadIdentityOwnerTypeCol, domain.WorkloadIdentityOwnerTypeApp),
		},
	), nil
}

func (p *workloadIdentityProjection) reduceOwnerRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*org.OrgRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(WorkloadIdentityInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(WorkloadIdentityResourceOwnerCol, e.Aggregate().ID),
		},
	), nil
}

// workloadIdentityRow mirrors the projection row fields carried by the added
// and changed event payloads.
type workloadIdentityRow struct {
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

func workloadIdentityCreateColumns(agg *eventstore.Aggregate, r workloadIdentityRow, creationDate time.Time, sequence uint64) []handler.Column {
	return []handler.Column{
		handler.NewCol(WorkloadIdentityIDCol, agg.ID),
		handler.NewCol(WorkloadIdentityCreationDateCol, creationDate),
		handler.NewCol(WorkloadIdentityChangeDateCol, creationDate),
		handler.NewCol(WorkloadIdentityResourceOwnerCol, agg.ResourceOwner),
		handler.NewCol(WorkloadIdentityInstanceIDCol, agg.InstanceID),
		handler.NewCol(WorkloadIdentitySequenceCol, sequence),
		handler.NewCol(WorkloadIdentityOwnerTypeCol, r.OwnerType),
		handler.NewCol(WorkloadIdentityOwnerIDCol, r.OwnerID),
		handler.NewCol(WorkloadIdentityNameCol, r.Name),
		handler.NewCol(WorkloadIdentityIssuerCol, r.Issuer),
		handler.NewCol(WorkloadIdentityJwksURICol, r.JwksURI),
		handler.NewCol(WorkloadIdentityAudiencesCol, database.TextArray[string](r.Audiences)),
		handler.NewCol(WorkloadIdentitySubjectCondsCol, marshalSubjectConditions(r.SubjectConditions)),
		handler.NewCol(WorkloadIdentityAlgorithmsCol, database.TextArray[string](r.Algorithms)),
		handler.NewCol(WorkloadIdentityStateCol, r.State),
	}
}

func marshalSubjectConditions(conditions []domain.SubjectCondition) []byte {
	//nolint:errcheck // conditions are validated before the event is pushed
	data, _ := json.Marshal(conditions)
	return data
}
