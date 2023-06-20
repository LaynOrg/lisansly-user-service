//go:build unit

package jwt_generator

import (
	"testing"
	"time"
	"user-api/pkg/config"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestUserEmail = "test@test.com"
	TestUserName  = "lynicis"
)

var (
	TestUserID = uuid.New().String()

	TestAmbiguousKey = []byte("AMBIGUOUS-KEY")
	TestPrivateKey   = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPaQZM9NX2H8lG9f+8MZ2eRSlqGsnj2yZMtfBYecCMmpoAoGCCqGSM49
AwEHoUQDQgAEHCnaSv1W3JI8jd+CkIZN1AUxldYWEYx9LACT245DA8dJJMx5TXP1
wtoFwCBLAORaw/fHr0X8MHUEstfqh3cTTg==
-----END EC PRIVATE KEY-----`)
	TestPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCnaSv1W3JI8jd+CkIZN1AUxldYW
EYx9LACT245DA8dJJMx5TXP1wtoFwCBLAORaw/fHr0X8MHUEstfqh3cTTg==
-----END PUBLIC KEY-----`)
)

func TestNewJwtGenerator(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		assert.NoError(t, err)
		assert.Implements(t, (*JwtGenerator)(nil), jwtGenerator)
	})

	t.Run("ambiguous ec256 private key", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestAmbiguousKey,
			PublicKey:  TestPublicKey,
		})

		assert.Error(t, err)
		assert.Nil(t, jwtGenerator)
	})

	t.Run("ambiguous ec256 private key", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestAmbiguousKey,
		})

		assert.Error(t, err)
		assert.Nil(t, jwtGenerator)
	})
}

func TestJwtGenerator_GenerateAccessToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		expirationDate := time.Now().UTC().Add(5 * time.Minute)
		token, err := jwtGenerator.GenerateAccessToken(
			expirationDate,
			TestUserName,
			TestUserEmail,
			TestUserID,
		)

		assert.NoError(t, err)
		assert.NotNil(t, token)
	})
}

func TestJwtGenerator_GenerateRefreshToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		expirationTime := time.Now().UTC().Add(24 * time.Hour)
		token, err := jwtGenerator.GenerateRefreshToken(expirationTime, TestUserID)

		assert.NoError(t, err)
		assert.NotNil(t, token)
	})
}

func TestJwtGenerator_VerifyAccessToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jwtGenerator, err := NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		expirationDate := time.Now().UTC().Add(5 * time.Minute)
		token, err := jwtGenerator.GenerateAccessToken(
			expirationDate,
			TestUserName,
			TestUserEmail,
			TestUserID,
		)
		require.NoError(t, err)

		var claims *Claims
		claims, err = jwtGenerator.VerifyAccessToken(token)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}
