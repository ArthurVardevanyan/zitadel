package query

import (
	"context"
	"database/sql"
	_ "embed"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// WorkloadIdentity is the projection model of a workload identity federation
// configuration, trusted by an application or service user (the owner).
type WorkloadIdentity struct {
	ID                string
	CreationDate      time.Time
	ChangeDate        time.Time
	ResourceOwner     string
	Sequence          uint64
	OwnerType         domain.WorkloadIdentityOwnerType
	OwnerID           string
	Name              string
	Issuer            string
	JwksURI           string
	Audiences         database.TextArray[string]
	SubjectConditions database.JSONArray[domain.SubjectCondition]
	Algorithms        database.TextArray[string]
	State             domain.WorkloadIdentityState
}

//go:embed workload_identity_by_owner.sql
var workloadIdentityByOwnerQuery string

//go:embed workload_identity_by_issuer.sql
var workloadIdentityByIssuerQuery string

// WorkloadIdentitiesByOwner returns all federation configurations of the given
// owner (management reads, permission is checked by the caller on the owner).
func (q *Queries) WorkloadIdentitiesByOwner(ctx context.Context, ownerType domain.WorkloadIdentityOwnerType, ownerID string) (_ []*WorkloadIdentity, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	return queryWorkloadIdentities(ctx, q.client.QueryContext, workloadIdentityByOwnerQuery,
		authz.GetInstance(ctx).InstanceID(), int32(ownerType), ownerID)
}

// ActiveWorkloadIdentitiesByIssuer returns the active federation configurations
// trusting the given issuer. This is the token endpoint hot path: the exact
// issuer URL must have been configured by some owner beforehand, so no
// attacker-controlled discovery URL is ever resolved.
func (q *Queries) ActiveWorkloadIdentitiesByIssuer(ctx context.Context, issuer string) (_ []*WorkloadIdentity, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	return queryWorkloadIdentities(ctx, q.client.QueryContext, workloadIdentityByIssuerQuery,
		authz.GetInstance(ctx).InstanceID(), issuer, int32(domain.WorkloadIdentityStateActive))
}

func queryWorkloadIdentities(
	ctx context.Context,
	queryContext func(context.Context, func(*sql.Rows) error, string, ...any) error,
	stmt string,
	args ...any,
) (_ []*WorkloadIdentity, err error) {
	identities := make([]*WorkloadIdentity, 0)
	err = queryContext(ctx, func(rows *sql.Rows) error {
		for rows.Next() {
			identity := new(WorkloadIdentity)
			var (
				ownerType sql.NullInt16
				state     sql.NullInt16
			)
			if err := rows.Scan(
				&identity.ID,
				&identity.CreationDate,
				&identity.ChangeDate,
				&identity.ResourceOwner,
				&identity.Sequence,
				&ownerType,
				&identity.OwnerID,
				&identity.Name,
				&identity.Issuer,
				&identity.JwksURI,
				&identity.Audiences,
				&identity.SubjectConditions,
				&identity.Algorithms,
				&state,
			); err != nil {
				return err
			}
			identity.OwnerType = domain.WorkloadIdentityOwnerType(ownerType.Int16)
			identity.State = domain.WorkloadIdentityState(state.Int16)
			identities = append(identities, identity)
		}
		return rows.Err()
	}, stmt, args...)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-Wif1a", "Errors.Internal")
	}
	return identities, nil
}
