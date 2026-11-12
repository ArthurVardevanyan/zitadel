package wif

import (
	"net/http"
	"time"
)

// Config controls the workload identity federation feature. It is part of the
// start configuration and read once at boot; configurations with Enabled false
// keep the entire feature dark: the management APIs answer Unimplemented and
// the OIDC token endpoint never consults federation configurations.
type Config struct {
	// Enabled activates workload identity federation for assertions
	// authenticated against trusted external OIDC issuers.
	Enabled bool
	// CacheTimeout is how long keys discovered from an external issuer are
	// cached before they are refetched. Unknown key ids trigger a refetch
	// regardless, rate limited to once per DefaultMinRefreshInterval.
	// Defaults to DefaultJWKSTTL when zero.
	CacheTimeout time.Duration
}

// Verifier builds the JWKS backed assertion verifier, or returns nil when the
// feature is disabled. All dependent code paths treat a nil verifier as
// fail-closed (reject) or fall back to regular credentials.
func (c Config) Verifier(httpClient *http.Client) *Verifier {
	if !c.Enabled {
		return nil
	}
	opts := []Option{WithHTTPClient(httpClient)}
	if c.CacheTimeout > 0 {
		opts = append(opts, WithJWKSTTL(c.CacheTimeout))
	}
	return New(opts...)
}
