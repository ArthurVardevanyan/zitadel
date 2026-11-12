package wif

import (
	"encoding/json"
	"time"

	"github.com/zitadel/zitadel/internal/zerrors"
)

// audience handles the aud claim presented either as a single string or as
// an array of strings (RFC 7519 §4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return zerrors.ThrowInvalidArgument(err, "WIF-Ver16", "invalid audience claim")
	}
	*a = many
	return nil
}

// jsonNumeric is a JWT NumericDate: seconds since the epoch, integral or
// fractional, optionally quoted.
type jsonNumeric int64

func (d *jsonNumeric) UnmarshalJSON(data []byte) error {
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return zerrors.ThrowInvalidArgument(err, "WIF-Ver18", "invalid numeric date")
	}
	*d = jsonNumeric(seconds)
	return nil
}

// jsonClaims is the wire format of the verified claims.
type jsonClaims struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  audience     `json:"aud"`
	Expiry    *jsonNumeric `json:"exp"`
	NotBefore *jsonNumeric `json:"nbf"`
	IssuedAt  *jsonNumeric `json:"iat"`
}

func parseClaims(payload []byte) (_ *Claims, err error) {
	var raw jsonClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, zerrors.ThrowInvalidArgument(err, "WIF-Ver17", "assertion payload unreadable")
	}
	claims := &Claims{
		Issuer:   raw.Issuer,
		Subject:  raw.Subject,
		Audience: raw.Audience,
	}
	if raw.Expiry != nil {
		claims.Expiry = time.Unix(int64(*raw.Expiry), 0)
	}
	if raw.NotBefore != nil {
		claims.NotBefore = time.Unix(int64(*raw.NotBefore), 0)
	}
	if raw.IssuedAt != nil {
		claims.IssuedAt = time.Unix(int64(*raw.IssuedAt), 0)
	}
	return claims, nil
}

// checkClaims enforces the rule's trust conditions and the time semantics on
// an already signature-verified set of claims.
func (v *Verifier) checkClaims(claims *Claims, rule *Rule) error {
	// exact issuer match, no prefix or case tricks
	if claims.Issuer != rule.Issuer {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver19", "assertion issuer mismatch")
	}
	if len(claims.Subject) == 0 {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver20", "assertion subject missing")
	}
	if !rule.subjectMatch(claims.Subject) {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver21", "assertion subject not allowed")
	}
	if len(claims.Audience) == 0 || !rule.audienceMatch(claims.Audience) {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver22", "assertion audience not allowed")
	}
	now := time.Now()
	if claims.Expiry.IsZero() {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver23", "assertion expiry missing")
	}
	if now.After(claims.Expiry.Add(v.skew)) {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver24", "assertion expired")
	}
	if !claims.NotBefore.IsZero() && claims.NotBefore.After(now.Add(v.skew)) {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver25", "assertion not yet valid")
	}
	if claims.IssuedAt.IsZero() {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver26", "assertion issue time missing")
	}
	if claims.IssuedAt.After(now.Add(v.skew)) {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver27", "assertion issued in the future")
	}
	if now.Sub(claims.IssuedAt) > v.maxAge+v.skew {
		return zerrors.ThrowPermissionDenied(nil, "WIF-Ver28", "assertion too old")
	}
	return nil
}
