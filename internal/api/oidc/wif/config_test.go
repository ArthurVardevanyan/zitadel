package wif

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigVerifier(t *testing.T) {
	// disabled feature stays dark: no verifier
	assert.Nil(t, Config{}.Verifier(http.DefaultClient))

	enabled := Config{Enabled: true}
	v := enabled.Verifier(http.DefaultClient)
	require.NotNil(t, v)
	assert.Equal(t, DefaultJWKSTTL, v.ttl)

	// the configured cache timeout overrides the default ttl
	v = Config{Enabled: true, CacheTimeout: time.Minute}.Verifier(http.DefaultClient)
	require.NotNil(t, v)
	assert.Equal(t, time.Minute, v.ttl)
}
