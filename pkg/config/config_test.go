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
		err := os.Setenv(DynamoDbUserTable, "database-user-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbUserUniquenessTable, "user-uniqueness-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbRefreshTokenHistoryTable, "database-refresh-token-history-table")
		require.NoError(t, err)

		err = os.Setenv(
			DynamoDbIdentityVerificationHistoryTable,
			"database-identity-verification-history-table",
		)
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

	t.Run("empty user uniqueness table", func(t *testing.T) {
		var err error

		err = os.Setenv(DynamoDbUserTable, "user-table")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadDynamoDbConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbUserUniquenessTable))
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

	t.Run("empty identity verification history table", func(t *testing.T) {
		var err error

		err = os.Setenv(DynamoDbUserTable, "user-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbUserUniquenessTable, "user-uniqueness-table")
		require.NoError(t, err)

		err = os.Setenv(DynamoDbRefreshTokenHistoryTable, "database-refresh-token-history-table")
		require.NoError(t, err)

		defer os.Clearenv()

		config, err := ReadDynamoDbConfig()

		assert.Equal(t, err, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbIdentityVerificationHistoryTable))
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

func TestReadSqsConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(AwsAccountId, "aws-account-id")
		require.NoError(t, err)

		err = os.Setenv(SQSEmailVerificationQueueUrl, "email-verification-queue-url")
		require.NoError(t, err)

		defer os.Clearenv()

		sqsConfig, err := ReadSqsConfig()

		assert.NoError(t, err)
		assert.NotEmpty(t, sqsConfig)
	})

	t.Run("empty aws account id", func(t *testing.T) {
		sqsConfig, err := ReadSqsConfig()

		assert.Error(t, err)
		assert.Empty(t, sqsConfig)
	})

	t.Run("empty sqs email verification queue url", func(t *testing.T) {
		var err error

		err = os.Setenv(AwsAccountId, "aws-account-id")
		require.NoError(t, err)

		defer os.Clearenv()

		sqsConfig, err := ReadSqsConfig()

		assert.Error(t, err)
		assert.Empty(t, sqsConfig)
	})
}
