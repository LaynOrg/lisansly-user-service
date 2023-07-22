//go:build unit

package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(ServerPort, "8080")
		require.NoError(t, err)

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		err = os.Setenv(MongodbDatabase, "database-database")
		require.NoError(t, err)

		err = os.Setenv(MongodbUserCollection, "database-user-collection")
		require.NoError(t, err)

		err = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
		require.NoError(t, err)

		err = os.Setenv(JwtPrivateKey, "jwt-private-key")
		require.NoError(t, err)

		err = os.Setenv(JwtPublicKey, "jwt-public-key")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, config)
	})

	t.Run("when server port is empty should return config", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		err = os.Setenv(MongodbDatabase, "database-database")
		require.NoError(t, err)

		err = os.Setenv(MongodbUserCollection, "database-user-collection")
		require.NoError(t, err)

		err = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
		require.NoError(t, err)

		err = os.Setenv(JwtPrivateKey, "jwt-private-key")
		require.NoError(t, err)

		err = os.Setenv(JwtPublicKey, "jwt-public-key")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, config)
	})
}

func TestReadMongoDbConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		err = os.Setenv(MongodbDatabase, "database-database")
		require.NoError(t, err)

		err = os.Setenv(MongodbUserCollection, "database-user-collection")
		require.NoError(t, err)

		err = os.Setenv(MongoDbRefreshTokenHistoryCollection, "database-refresh-token-collection")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, mongoConfig)
	})

	t.Run("empty database uri", func(t *testing.T) {
		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})

	t.Run("empty database username", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})

	t.Run("empty database password", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})

	t.Run("empty database name", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})

	t.Run("empty user collection name", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		err = os.Setenv(MongodbDatabase, "database-database")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})

	t.Run("empty refresh token collection name", func(t *testing.T) {
		var err error

		err = os.Setenv(MongodbUri, "database-uri")
		require.NoError(t, err)

		err = os.Setenv(MongodbUsername, "database-username")
		require.NoError(t, err)

		err = os.Setenv(MongodbPassword, "database-password")
		require.NoError(t, err)

		err = os.Setenv(MongodbDatabase, "database-database")
		require.NoError(t, err)

		err = os.Setenv(MongodbUserCollection, "database-user-collection")
		require.NoError(t, err)

		defer os.Clearenv()

		mongoConfig, err := ReadMongoDbConfig()

		assert.Error(t, err)
		assert.Empty(t, mongoConfig)
	})
}

func TestReadJwtConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(JwtPrivateKey, "jwt-private-key")
		require.NoError(t, err)

		err = os.Setenv(JwtPublicKey, "jwt-public-key")
		require.NoError(t, err)

		defer os.Clearenv()

		jwtConfig, err := ReadJwtConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, jwtConfig)
	})

	t.Run("empty private key", func(t *testing.T) {
		var err error

		jwtConfig, err := ReadJwtConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey))
		assert.Empty(t, jwtConfig)
	})

	t.Run("empty public key", func(t *testing.T) {
		var err error

		err = os.Setenv(JwtPublicKey, "jwt-public-key")
		require.NoError(t, err)

		defer os.Clearenv()

		jwtConfig, err := ReadJwtConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey))
		assert.Empty(t, jwtConfig)
	})
}
