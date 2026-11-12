package domain

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// WorkloadIdentityOwnerType distinguishes the two principals a federation
// configuration can be attached to.
type WorkloadIdentityOwnerType int32

const (
	WorkloadIdentityOwnerTypeApp WorkloadIdentityOwnerType = iota
	WorkloadIdentityOwnerTypeServiceUser
)

//go:generate enumer -type WorkloadIdentityOwnerType -transform snake -trimprefix WorkloadIdentityOwnerType

// WorkloadIdentityState is the lifecycle state of a federation configuration.
type WorkloadIdentityState int32

const (
	// WorkloadIdentityStateUnspecified is the zero value, only used in write
	// models to indicate that no configuration with the given ID exists.
	WorkloadIdentityStateUnspecified WorkloadIdentityState = iota
	WorkloadIdentityStateActive
	WorkloadIdentityStateInactive
)

//go:generate enumer -type WorkloadIdentityState -transform snake -trimprefix WorkloadIdentityState

// SubjectMatchType selects how a SubjectCondition value is compared to an
// assertion's `sub` claim.
type SubjectMatchType int32

const (
	SubjectMatchTypeExact SubjectMatchType = iota
	SubjectMatchTypePrefix
	SubjectMatchTypeRegex
)

//go:generate enumer -type SubjectMatchType -transform snake -trimprefix SubjectMatchType

// defaultWorkloadIdentityAlgorithms is the signature allowlist used when a
// configuration does not specify one. Only asymmetric algs are permitted.
var defaultWorkloadIdentityAlgorithms = []string{"RS256", "ES384", "ES512", "EdDSA"}

// allowedWorkloadIdentityAlgorithms is the complete set of accepted signing
// algorithms. `none` and MAC-based algs are intentionally absent.
var allowedWorkloadIdentityAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// SubjectCondition restricts which `sub` claim values an external issuer may
// present for a given owner.
type SubjectCondition struct {
	MatchType SubjectMatchType
	Value     string
}

// compile checks the condition value is usable (valid regex when needed).
func (c SubjectCondition) compile() error {
	if c.Value == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif1", "Errors.WorkloadIdentity.SubjectCondition.Empty")
	}
	if c.MatchType == SubjectMatchTypeRegex {
		if _, err := regexp.Compile(c.Value); err != nil {
			return zerrors.ThrowInvalidArgument(err, "DOMAIN-wif2", "Errors.WorkloadIdentity.SubjectCondition.InvalidRegex")
		}
	}
	return nil
}

// WorkloadIdentityFederation is the domain model of a single federation rule
// attached to an application or service user.
type WorkloadIdentityFederation struct {
	models.ObjectRoot

	InstanceID string

	OwnerType         WorkloadIdentityOwnerType
	OwnerID           string
	Name              string
	Issuer            string
	JwksURI           string
	Audiences         []string
	SubjectConditions []SubjectCondition
	Algorithms        []string
	State             WorkloadIdentityState
}

// EffectiveAlgorithms returns the configured algorithms or the default set
// when none were provided.
func (f *WorkloadIdentityFederation) EffectiveAlgorithms() []string {
	if len(f.Algorithms) == 0 {
		return defaultWorkloadIdentityAlgorithms
	}
	return f.Algorithms
}

// IsValid validates all fields of the federation before it can be persisted.
func (f *WorkloadIdentityFederation) IsValid() error {
	if f.OwnerID == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif3", "Errors.WorkloadIdentity.OwnerMissing")
	}
	if strings.TrimSpace(f.Name) == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif4", "Errors.WorkloadIdentity.NameMissing")
	}
	if err := validateWorkloadIdentityIssuer(f.Issuer); err != nil {
		return err
	}
	if f.JwksURI != "" {
		if err := validateWorkloadIdentityHTTPSURL(f.JwksURI, "DOMAIN-wif11", "Errors.WorkloadIdentity.JwksURIInvalid"); err != nil {
			return err
		}
	}
	if len(f.Audiences) == 0 {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif5", "Errors.WorkloadIdentity.AudienceRequired")
	}
	if len(f.SubjectConditions) == 0 {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif6", "Errors.WorkloadIdentity.SubjectConditionRequired")
	}
	for _, c := range f.SubjectConditions {
		if err := c.compile(); err != nil {
			return err
		}
	}
	for _, alg := range f.Algorithms {
		if !allowedWorkloadIdentityAlgorithms[alg] {
			return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif7", "Errors.WorkloadIdentity.AlgorithmNotAllowed")
		}
	}
	if f.State != WorkloadIdentityStateActive && f.State != WorkloadIdentityStateInactive {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif14", "Errors.WorkloadIdentity.StateInvalid")
	}
	return nil
}

// validateWorkloadIdentityIssuer checks the issuer is an https URL without
// query or fragment, matching RFC 8414 §3.3 normalization expectations.
func validateWorkloadIdentityIssuer(issuer string) error {
	if issuer == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif8", "Errors.WorkloadIdentity.IssuerRequired")
	}
	if err := validateWorkloadIdentityHTTPSURL(issuer, "DOMAIN-wif9", "Errors.WorkloadIdentity.IssuerInvalid"); err != nil {
		return err
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return zerrors.ThrowInvalidArgument(err, "DOMAIN-wif13", "Errors.WorkloadIdentity.IssuerInvalid")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-wif10", "Errors.WorkloadIdentity.IssuerInvalid")
	}
	return nil
}

func validateWorkloadIdentityHTTPSURL(rawURL, id, message string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return zerrors.ThrowInvalidArgument(err, id, message)
	}
	if u.Scheme != "https" || u.Host == "" {
		return zerrors.ThrowInvalidArgument(nil, id, message)
	}
	return nil
}
