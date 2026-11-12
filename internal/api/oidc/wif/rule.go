// Package wif verifies JWT assertions signed by third-party OpenID Connect
// issuers, implementing Workload Identity Federation. A Rule binds one
// external issuer to a principal and describes the exact trust conditions;
// the Verifier checks an assertion against a Rule without any Zitadel
// specific key material.
package wif

import (
	"regexp"
	"strings"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// Rule is the verifier-side view of a workload identity federation
// configuration. It is deliberately decoupled from the domain and query
// models so the verifier can be unit tested with plain structs.
type Rule struct {
	// Issuer is the exact iss the assertion must carry.
	Issuer string
	// JwksURI optionally overrides RFC 8414 discovery of the signing keys.
	JwksURI string
	// Audiences lists accepted aud values; the assertion must match at least one.
	Audiences []string
	// SubjectConditions restricts the sub claim; at least one must match.
	SubjectConditions []domain.SubjectCondition
	// Algorithms is the allowed signature set. Empty means the domain default.
	Algorithms []string
}

// effectiveAlgorithms resolves the allowed signature algorithms.
func (r *Rule) effectiveAlgorithms() []string {
	if len(r.Algorithms) == 0 {
		return domain.DefaultWorkloadIdentityAlgorithms
	}
	return r.Algorithms
}

// audienceMatch reports whether any aud value is in the allowed set.
func (r *Rule) audienceMatch(aud audience) bool {
	for _, want := range r.Audiences {
		for _, got := range aud {
			if want == got {
				return true
			}
		}
	}
	return false
}

// subjectMatch reports whether sub satisfies at least one condition.
func (r *Rule) subjectMatch(sub string) bool {
	for _, condition := range r.SubjectConditions {
		if conditionMatch(condition, sub) {
			return true
		}
	}
	return false
}

func conditionMatch(condition domain.SubjectCondition, sub string) bool {
	switch condition.MatchType {
	case domain.SubjectMatchTypeExact:
		return sub == condition.Value
	case domain.SubjectMatchTypePrefix:
		return strings.HasPrefix(sub, condition.Value)
	case domain.SubjectMatchTypeRegex:
		// values are validated as regexes on write; ignore a compile failure
		// defensively and treat it as no-match.
		matched, err := regexp.MatchString(condition.Value, sub)
		return err == nil && matched
	default:
		return false
	}
}

// validateRule checks the minimum invariants the verifier relies on.
func validateRule(rule *Rule) error {
	if rule == nil {
		return zerrors.ThrowInvalidArgument(nil, "WIF-Ver01", "Errors.WorkloadIdentity.NotFound")
	}
	if rule.Issuer == "" {
		return zerrors.ThrowInvalidArgument(nil, "WIF-Ver02", "Errors.WorkloadIdentity.IssuerRequired")
	}
	if len(rule.Audiences) == 0 {
		return zerrors.ThrowInvalidArgument(nil, "WIF-Ver03", "Errors.WorkloadIdentity.AudienceRequired")
	}
	if len(rule.SubjectConditions) == 0 {
		return zerrors.ThrowInvalidArgument(nil, "WIF-Ver04", "Errors.WorkloadIdentity.SubjectConditionRequired")
	}
	return nil
}
