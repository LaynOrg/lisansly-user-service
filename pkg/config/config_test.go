//go:build unit

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		_ = os.Setenv(ServerPort, "8080")
		_ = os.Setenv(MongodbUri, "database-uri")
		_ = os.Setenv(MongodbUsername, "database-username")
		_ = os.Setenv(MongodbPassword, "database-password")
		_ = os.Setenv(MongodbDatabase, "database-database")
		_ = os.Setenv(MongodbUserCollection, "database-user-collection")
		_ = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
		_ = os.Setenv(JwtPrivateKey, "jwt-private-key")
		_ = os.Setenv(JwtPublicKey, "jwt-public-key")
		defer os.Clearenv()

		config, err := ReadConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, config)
	})

	t.Run("when server port is empty should return config", func(t *testing.T) {
		_ = os.Setenv(MongodbUri, "database-uri")
		_ = os.Setenv(MongodbUsername, "database-username")
		_ = os.Setenv(MongodbPassword, "database-password")
		_ = os.Setenv(MongodbDatabase, "database-database")
		_ = os.Setenv(MongodbUserCollection, "database-user-collection")
		_ = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
		_ = os.Setenv(JwtPrivateKey, "jwt-private-key")
		_ = os.Setenv(JwtPublicKey, "jwt-public-key")
		defer os.Clearenv()

		config, err := ReadConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, config)
	})
}

func TestReadMongoDbConfig(t *testing.T) {
	_ = os.Setenv(MongodbUri, "database-uri")
	_ = os.Setenv(MongodbUsername, "database-username")
	_ = os.Setenv(MongodbPassword, "database-password")
	_ = os.Setenv(MongodbDatabase, "database-database")
	_ = os.Setenv(MongodbUserCollection, "database-user-collection")
	_ = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
	defer os.Clearenv()

	mongoConfig, err := ReadMongoDbConfig()

	assert.NoError(t, err)
	assert.NotEmpty(t, mongoConfig)
}

func TestReadJwtConfig(t *testing.T) {
	_ = os.Setenv(JwtPrivateKey, "jwt-private-key")
	_ = os.Setenv(JwtPublicKey, "jwt-public-key")
	defer os.Clearenv()

	jwtConfig, err := ReadJwtConfig()

	assert.NoError(t, err)
	assert.NotEmpty(t, jwtConfig)
}
