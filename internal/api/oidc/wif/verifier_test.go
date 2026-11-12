package wif

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel/internal/domain"
)

type keySetHolder struct {
	value atomic.Value // jose.JSONWebKeySet
}

func (h *keySetHolder) set(keys ...jose.JSONWebKey) { h.value.Store(jose.JSONWebKeySet{Keys: keys}) }

func (h *keySetHolder) get() jose.JSONWebKeySet {
	set, _ := h.value.Load().(jose.JSONWebKeySet)
	return set
}

// issuerFixture is an HTTPS test server acting as an OIDC issuer: mutable
// JWKS at /keys plus a consistent discovery document, so rules with and
// without a jwks_uri override can be verified against one trusted client.
type issuerFixture struct {
	base     string
	client   *http.Client
	requests *atomic.Int64
	keys     *keySetHolder
}

func newIssuerFixture(t *testing.T) *issuerFixture {
	t.Helper()
	iss := &issuerFixture{requests: new(atomic.Int64), keys: new(keySetHolder)}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		iss.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iss.keys.get())
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   iss.base,
			"jwks_uri": iss.base + "/keys",
		})
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	iss.base = server.URL
	iss.client = server.Client()
	return iss
}

func (i *issuerFixture) rule() *Rule {
	return &Rule{
		Issuer:            i.base,
		JwksURI:           i.base + "/keys",
		Audiences:         []string{"zitadel"},
		SubjectConditions: []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypeExact, Value: "ci-runner"}},
	}
}

func (i *issuerFixture) discoveryRule() *Rule {
	rule := i.rule()
	rule.JwksURI = ""
	return rule
}

func newVerifier(client *http.Client) *Verifier {
	return New(WithHTTPClient(client), WithMinRefreshInterval(0))
}

func newRSAKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "RS256", Use: "sig"}
}

func newECKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "ES256", Use: "sig"}
}

func newEdKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: "EdDSA", Use: "sig"}
}

// sign marshals claims and signs them as a compact JWS with the key's kid in
// the protected header.
func sign(t *testing.T, key jose.JSONWebKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": key.KeyID}},
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := obj.CompactSerialize()
	require.NoError(t, err)
	return token
}

func standardClaims(iss string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": iss,
		"sub": "ci-runner",
		"aud": "zitadel",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
}

func TestVerifyHappyPaths(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		key  func(*testing.T, string) jose.JSONWebKey
	}{
		{"RS256", newRSAKey},
		{"ES256", newECKey},
		{"EdDSA", newEdKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss := newIssuerFixture(t)
			key := tc.key(t, "k1")
			iss.keys.set(key.Public())

			got, err := newVerifier(iss.client).Verify(ctx, sign(t, key, standardClaims(iss.base)), iss.rule())
			require.NoError(t, err)
			assert.Equal(t, iss.base, got.Issuer)
			assert.Equal(t, "ci-runner", got.Subject)
			assert.Equal(t, audience{"zitadel"}, got.Audience)
		})
	}
}

func TestVerifyDiscovery(t *testing.T) {
	ctx := context.Background()
	iss := newIssuerFixture(t)
	key := newRSAKey(t, "k1")
	iss.keys.set(key.Public())

	got, err := newVerifier(iss.client).Verify(ctx, sign(t, key, standardClaims(iss.base)), iss.discoveryRule())
	require.NoError(t, err)
	assert.Equal(t, "ci-runner", got.Subject)
}

func TestVerifyRejections(t *testing.T) {
	ctx := context.Background()

	t.Run("issuer mismatch", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, standardClaims("https://evil")), iss.rule())
		require.Error(t, err)
	})

	t.Run("wrong audience", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["aud"] = "someone-else"
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("audience array match", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["aud"] = []string{"other", "zitadel"}
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.NoError(t, err)
	})

	t.Run("subject rejected", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["sub"] = "attacker"
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("alg not allowed", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		rule := iss.rule()
		rule.Algorithms = []string{"ES256"}
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, standardClaims(iss.base)), rule)
		require.Error(t, err, "RS256 rejected when only ES256 allowed")
	})

	t.Run("expired", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("expiry inside skew accepted", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["exp"] = time.Now().Add(-5 * time.Second).Unix()
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.NoError(t, err)
	})

	t.Run("not yet valid", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["nbf"] = time.Now().Add(time.Hour).Unix()
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("too old by max age", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("future iat rejected", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		claims["iat"] = time.Now().Add(time.Hour).Unix()
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("garbage input", func(t *testing.T) {
		iss := newIssuerFixture(t)
		_, err := newVerifier(iss.client).Verify(ctx, "not-a-jwt", iss.rule())
		require.Error(t, err)
	})

	t.Run("missing exp rejected", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set(key.Public())
		claims := standardClaims(iss.base)
		delete(claims, "exp")
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), iss.rule())
		require.Error(t, err)
	})

	t.Run("unsigned keys rejected", func(t *testing.T) {
		iss := newIssuerFixture(t)
		key := newRSAKey(t, "k1")
		iss.keys.set() // issuer serves no keys at all
		_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, standardClaims(iss.base)), iss.rule())
		require.Error(t, err)
	})
}

func TestVerifySubjectConditions(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		conditions []domain.SubjectCondition
		sub        string
		valid      bool
	}{
		{"exact match", []domain.SubjectCondition{{Value: "repo:org/repo:ref:main"}}, "repo:org/repo:ref:main", true},
		{"exact mismatch", []domain.SubjectCondition{{Value: "other"}}, "repo:org/repo:ref:main", false},
		{"prefix match", []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypePrefix, Value: "repo:org/"}}, "repo:org/repo:ref:main", true},
		{"prefix mismatch", []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypePrefix, Value: "repo:evil/"}}, "repo:org/repo:ref:main", false},
		{"regex match", []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypeRegex, Value: `repo:org/repo:ref:refs/heads/main`}}, "repo:org/repo:ref:refs/heads/main", true},
		{"regex mismatch", []domain.SubjectCondition{{MatchType: domain.SubjectMatchTypeRegex, Value: `^repo:org/repo:ref:refs/tags/.*$`}}, "repo:org/repo:ref:refs/heads/main", false},
		{"any of multiple", []domain.SubjectCondition{{Value: "nope"}, {MatchType: domain.SubjectMatchTypePrefix, Value: "repo:"}}, "repo:org/repo", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss := newIssuerFixture(t)
			key := newRSAKey(t, "k1")
			iss.keys.set(key.Public())
			rule := iss.rule()
			rule.SubjectConditions = tc.conditions
			claims := standardClaims(iss.base)
			claims["sub"] = tc.sub
			_, err := newVerifier(iss.client).Verify(ctx, sign(t, key, claims), rule)
			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestVerifyKeyRotationRefetch(t *testing.T) {
	ctx := context.Background()
	iss := newIssuerFixture(t)
	first := newRSAKey(t, "k1")
	iss.keys.set(first.Public())

	v := newVerifier(iss.client)
	rule := iss.rule()

	// first verification fetches the key set once
	_, err := v.Verify(ctx, sign(t, first, standardClaims(iss.base)), rule)
	require.NoError(t, err)
	require.Equal(t, int64(1), iss.requests.Load())

	// second verification is served from cache
	_, err = v.Verify(ctx, sign(t, first, standardClaims(iss.base)), rule)
	require.NoError(t, err)
	require.Equal(t, int64(1), iss.requests.Load())

	// the issuer rotates to a new key: the unknown kid forces exactly one
	// refetch which resolves it
	second := newECKey(t, "k2")
	iss.keys.set(first.Public(), second.Public())
	_, err = v.Verify(ctx, sign(t, second, standardClaims(iss.base)), rule)
	require.NoError(t, err)
	require.Equal(t, int64(2), iss.requests.Load())
}
