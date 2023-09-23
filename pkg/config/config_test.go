//go:build unit

package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadDynamoDbConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		err := os.Setenv(DynamoDbUserTable, "database-user-collection")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbUserUniquenessTable, "user-uniqueness-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbRefreshTokenHistoryTable, "database-refresh-token-collection")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadDynamoDbConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, config)
	})

	t.Run("empty user table", func(t *testing.T) {
		config, err := ReadDynamoDbConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbUserTable))
		assert.Empty(t, config)
	})

	t.Run("empty refresh token history table", func(t *testing.T) {
		var err error

		err = os.Setenv(DynamoDbUserTable, "user-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbUserUniquenessTable, "user-uniqueness-table")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadDynamoDbConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbRefreshTokenHistoryTable))
		assert.Empty(t, config)
	})

	t.Run("empty user uniqueness table", func(t *testing.T) {
		var err error

		err = os.Setenv(DynamoDbUserTable, "user-table")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadDynamoDbConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbUserUniquenessTable))
		assert.Empty(t, config)
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

		err = os.Setenv(JwtPrivateKey, "jwt-private-key")
		require.NoError(t, err)

		defer os.Clearenv()

		jwtConfig, err := ReadJwtConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, JwtPublicKey))
		assert.Empty(t, jwtConfig)
	})
}
