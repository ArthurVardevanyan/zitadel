package workload_identity

import (
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
)

const (
	// UniqueIssuerSubject reserves an (issuer, exact subject) pair so that a
	// service user assertion can never map ambiguously to two users.
	UniqueIssuerSubject = "workload_identity_issuer_subject"
	// DuplicateIssuerSubject is the localization key surfaced on conflict.
	DuplicateIssuerSubject = "Errors.WorkloadIdentity.SubjectCondition.AlreadyExists"
)

// NewAddUniqueConstraints returns the unique constraints an added or changed
// configuration must reserve. Only configurations owned by a service user are
// reserved: application authentication is selected by the client_id of the
// request, so duplicate (issuer, subject) pairs across apps are unambiguous.
// Prefix and regex conditions cannot be reserved; overlaps are resolved at
// runtime by rejecting ambiguous resolutions.
func NewAddUniqueConstraints(ownerType domain.WorkloadIdentityOwnerType, ownerID, issuer string, conditions []domain.SubjectCondition) []*eventstore.UniqueConstraint {
	if ownerType != domain.WorkloadIdentityOwnerTypeServiceUser {
		return nil
	}
	constraints := make([]*eventstore.UniqueConstraint, 0, len(conditions))
	for _, condition := range conditions {
		if condition.MatchType != domain.SubjectMatchTypeExact {
			continue
		}
		constraints = append(constraints, eventstore.NewAddEventUniqueConstraint(
			UniqueIssuerSubject,
			issuerSubjectField(issuer, condition.Value),
			DuplicateIssuerSubject,
		).WithOwners(eventstore.OwnerTag(eventstore.UniqueConstraintOwnerUser, ownerID)))
	}
	return constraints
}

// NewRemoveUniqueConstraints releases the constraints of a configuration that
// is removed or moved away from the reserved (issuer, subject) pairs.
func NewRemoveUniqueConstraints(ownerType domain.WorkloadIdentityOwnerType, ownerID, issuer string, conditions []domain.SubjectCondition) []*eventstore.UniqueConstraint {
	if ownerType != domain.WorkloadIdentityOwnerTypeServiceUser {
		return nil
	}
	constraints := make([]*eventstore.UniqueConstraint, 0, len(conditions))
	for _, condition := range conditions {
		if condition.MatchType != domain.SubjectMatchTypeExact {
			continue
		}
		constraints = append(constraints, eventstore.NewRemoveUniqueConstraint(
			UniqueIssuerSubject,
			issuerSubjectField(issuer, condition.Value),
		))
	}
	return constraints
}

func issuerSubjectField(issuer, subject string) string {
	return issuer + "|" + subject
}
