package wif

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const (
	// DefaultJWKSTTL bounds how long a fetched key set is reused before the
	// issuer is queried again.
	DefaultJWKSTTL = 10 * time.Minute
	// DefaultMinRefreshInterval rate limits forced refetches caused by an
	// unknown key id, bounding the DoS surface an issuer is exposed to.
	DefaultMinRefreshInterval = 10 * time.Second
	// DefaultClockSkew matches the established Zitadel assertion tolerance.
	DefaultClockSkew = 10 * time.Second
	// DefaultMaxAge caps assertion age (now - iat), mirroring the one hour
	// bound of the Zitadel JWT-profile verifier.
	DefaultMaxAge = time.Hour
	// DefaultFetchTimeout bounds a single discovery or JWKS request.
	DefaultFetchTimeout = 10 * time.Second
	// maxJWKSSize caps the accepted JWKS body.
	maxJWKSSize = 1 << 20 // 1 MiB
	// maxDiscoverySize caps the accepted discovery document.
	maxDiscoverySize = 1 << 15 // 32 KiB
)

// Claims are the verified claims of an assertion.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  audience
	Expiry    time.Time
	NotBefore time.Time
	IssuedAt  time.Time
}

// Verifier verifies JWT assertions against Rules. It fetches each issuer's
// signing keys through OIDC discovery (or an explicit jwks_uri override) and
// caches them per issuer. Only issuers with a Rule ever receive a request.
type Verifier struct {
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration
	skew       time.Duration
	maxAge     time.Duration
	issuers    map[string]*keyCacheEntry
	mu         sync.Mutex
}

// Option customizes a Verifier.
type Option func(*Verifier)

// WithHTTPClient sets the client used for discovery and JWKS requests. The
// caller is responsible for its TLS configuration.
func WithHTTPClient(client *http.Client) Option {
	return func(v *Verifier) {
		if client != nil {
			v.client = client
		}
	}
}

// WithClockSkew overrides the accepted time skew for exp/nbf/iat checks.
func WithClockSkew(skew time.Duration) Option {
	return func(v *Verifier) { v.skew = skew }
}

// WithJWKSTTL overrides the key set cache duration.
func WithJWKSTTL(ttl time.Duration) Option {
	return func(v *Verifier) { v.ttl = ttl }
}

// WithMinRefreshInterval overrides the rate limit for forced refetches
// triggered by unknown key ids.
func WithMinRefreshInterval(interval time.Duration) Option {
	return func(v *Verifier) { v.minRefresh = interval }
}

// WithMaxAge overrides the maximum accepted assertion age.
func WithMaxAge(maxAge time.Duration) Option {
	return func(v *Verifier) { v.maxAge = maxAge }
}

// New builds a Verifier with default settings.
func New(opts ...Option) *Verifier {
	v := &Verifier{
		client:     &http.Client{},
		ttl:        DefaultJWKSTTL,
		minRefresh: DefaultMinRefreshInterval,
		skew:       DefaultClockSkew,
		maxAge:     DefaultMaxAge,
		issuers:    make(map[string]*keyCacheEntry),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// keyCacheEntry caches the key set of one issuer. The embedded mutex
// serializes refetches per issuer; concurrent waiters observe the refreshed
// entry without issuing their own request (singleflight semantics).
type keyCacheEntry struct {
	mu      sync.Mutex
	keys    *jose.JSONWebKeySet
	fetched time.Time
}

// Verify parses and validates rawJWT against rule. The JOSE header algorithm
// must be allowed by the rule (never the assertion itself deciding), the
// signature must verify with a key from the issuer's key set and iss, aud,
// sub, exp, nbf and iat are checked as documented on Rule.
func (v *Verifier) Verify(ctx context.Context, rawJWT string, rule *Rule) (_ *Claims, err error) {
	if err := validateRule(rule); err != nil {
		return nil, err
	}

	// ParseSigned is given the allowlist up front: the parsed JWS will refuse
	// any other signature algorithm, so a signed-but-wrong-alg token never
	// reaches verification.
	obj, err := jose.ParseSigned(rawJWT, joseAlgorithms(rule.effectiveAlgorithms()))
	if err != nil {
		return nil, zerrors.ThrowInvalidArgument(err, "WIF-Ver05", "assertion parse error")
	}
	if len(obj.Signatures) != 1 {
		return nil, zerrors.ThrowInvalidArgument(nil, "WIF-Ver06", "assertion must carry exactly one signature")
	}

	payload, err := v.verifySignature(ctx, obj, rule)
	if err != nil {
		return nil, err
	}

	claims, err := parseClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := v.checkClaims(claims, rule); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Verifier) verifySignature(ctx context.Context, obj *jose.JSONWebSignature, rule *Rule) ([]byte, error) {
	kid := obj.Signatures[0].Header.KeyID
	keys, err := v.keySet(ctx, rule)
	if err != nil {
		return nil, err
	}
	if payload, ok := verifyWith(obj, keys, kid); ok {
		return payload, nil
	}
	// The key is unknown: the issuer likely rotated keys. Refetch once
	// (rate limited by minRefresh) and retry.
	_ = v.refresh(ctx, rule)
	keys, err = v.keySet(ctx, rule)
	if err != nil {
		return nil, err
	}
	if payload, ok := verifyWith(obj, keys, kid); ok {
		return payload, nil
	}
	return nil, zerrors.ThrowPermissionDenied(nil, "WIF-Ver07", "no key of the issuer verifies the assertion")
}

// verifyWith verifies the signature, selecting keys by kid when the header
// names one. Without kid every signing key is tried.
func verifyWith(obj *jose.JSONWebSignature, keys *jose.JSONWebKeySet, kid string) ([]byte, bool) {
	for _, key := range keys.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if kid != "" && key.KeyID != kid {
			continue
		}
		if payload, err := obj.Verify(key); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// keySet returns a valid cached key set for the rule, fetching it when the
// cache is empty or stale.
func (v *Verifier) keySet(ctx context.Context, rule *Rule) (*jose.JSONWebKeySet, error) {
	entry := v.entry(rule.Issuer)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.keys != nil && time.Since(entry.fetched) < v.ttl {
		return entry.keys, nil
	}
	if err := v.fetchLocked(ctx, entry, rule); err != nil {
		// Serve the stale key set when the issuer is momentarily
		// unavailable: signature verification with a real, previously valid
		// key is still safe.
		if entry.keys != nil {
			return entry.keys, nil
		}
		return nil, err
	}
	return entry.keys, nil
}

// refresh forces a refetch, rate limited so repeated unknown-kid assertions
// cannot hammer the issuer. It ignores errors; the next keySet call observes
// either a fresh or the still cached set.
func (v *Verifier) refresh(ctx context.Context, rule *Rule) error {
	entry := v.entry(rule.Issuer)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if !entry.fetched.IsZero() && time.Since(entry.fetched) < v.minRefresh {
		return nil
	}
	return v.fetchLocked(ctx, entry, rule)
}

func (v *Verifier) entry(issuer string) *keyCacheEntry {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.issuers[issuer]
	if !ok {
		entry = new(keyCacheEntry)
		v.issuers[issuer] = entry
	}
	return entry
}

// fetchLocked resolves the JWKS location and fetches the key set. entry.mu
// must be held.
func (v *Verifier) fetchLocked(ctx context.Context, entry *keyCacheEntry, rule *Rule) error {
	jwksURI := rule.JwksURI
	if jwksURI == "" {
		discovered, err := v.discover(ctx, rule.Issuer)
		if err != nil {
			return err
		}
		jwksURI = discovered
	}
	keys, err := v.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return err
	}
	entry.keys = keys
	entry.fetched = time.Now()
	return nil
}

// discover resolves jwks_uri via RFC 8414 discovery, requiring the document
// to be consistent with the exact issuer.
func (v *Verifier) discover(ctx context.Context, issuer string) (string, error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JwksURI string `json:"jwks_uri"`
	}
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	if err := v.getJSON(ctx, url, maxDiscoverySize, &doc); err != nil {
		return "", err
	}
	if doc.JwksURI == "" {
		return "", zerrors.ThrowInvalidArgument(nil, "WIF-Ver08", "discovery document without jwks_uri")
	}
	if doc.Issuer != "" && doc.Issuer != issuer {
		return "", zerrors.ThrowInvalidArgument(nil, "WIF-Ver09", "discovery document issuer mismatch")
	}
	return doc.JwksURI, nil
}

func (v *Verifier) fetchJWKS(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {
	keys := new(jose.JSONWebKeySet)
	if err := v.getJSON(ctx, url, maxJWKSSize, keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// getJSON GETs url and decodes a size limited JSON body. Redirects are not
// followed: the target of a redirect is not constrained by the rule.
func (v *Verifier) getJSON(ctx context.Context, url string, limit int64, dst any) error {
	if !strings.HasPrefix(url, "https://") {
		return zerrors.ThrowInvalidArgument(nil, "WIF-Ver10", "only https key sources are allowed")
	}
	reqCtx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return zerrors.ThrowInvalidArgument(err, "WIF-Ver11", "invalid key source url")
	}
	client := *v.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return zerrors.ThrowUnavailable(err, "WIF-Ver12", "key source request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zerrors.ThrowUnavailable(nil, "WIF-Ver13", "key source responded with an error status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return zerrors.ThrowUnavailable(err, "WIF-Ver14", "key source response unreadable")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return zerrors.ThrowUnavailable(err, "WIF-Ver15", "key source response malformed")
	}
	return nil
}

// joseAlgorithms maps the rule's allowlist to JOSE algorithms. Only
// asymmetric algorithms are ever mapped; the domain validation restricts the
// persisted set, and unknown names are dropped here defensively.
func joseAlgorithms(algorithms []string) []jose.SignatureAlgorithm {
	seen := make(map[string]bool, len(algorithms))
	for _, alg := range algorithms {
		seen[alg] = true
	}
	out := make([]jose.SignatureAlgorithm, 0, len(algorithms))
	for _, name := range []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"} {
		if seen[name] {
			out = append(out, jose.SignatureAlgorithm(name))
		}
	}
	if len(out) == 0 {
		// domain validation guarantees a non-empty set; be defensive.
		for _, name := range domain.DefaultWorkloadIdentityAlgorithms {
			out = append(out, jose.SignatureAlgorithm(name))
		}
	}
	return out
}
