//go:build unit

package user

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

const (
	TestAwsRegion                        = "us-west-1"
	TestDynamoDbUserTable                = "user"
	TestDynamoDbUserUniquenessTable      = "user-uniqueness"
	TestDynamoDbRefreshTokenHistoryTable = "refresh-token-history"
)

func TestNewRepository(t *testing.T) {
	repository := NewRepository(nil, nil)

	assert.Implements(t, (*Repository)(nil), repository)
}

func TestRepository_InsertUser(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)
		createUserUniquenessTable(t, ctx, dynamodbClient)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			},
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, cerr)
	})

	t.Run("when user already exist in table should return error", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)
		createUserUniquenessTable(t, ctx, dynamodbClient)

		fakeUserItem, err := attributevalue.MarshalMap(&Table{
			Id:        TestUserId,
			Name:      TestUserName,
			Email:     TestEmail,
			Password:  TestPassword,
			Role:      RoleUser,
			CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)

		fakeUserUniquenessItem, err := attributevalue.MarshalMap(&UniquenessTable{
			Unique: TestEmail,
			Type:   UniquenessEmail,
		})
		require.NoError(t, err)

		_, err = dynamodbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []types.TransactWriteItem{
				{
					Put: &types.Put{
						Item:      fakeUserItem,
						TableName: aws.String(TestDynamoDbUserTable),
					},
				},
				{
					Put: &types.Put{
						Item:      fakeUserUniquenessItem,
						TableName: aws.String(TestDynamoDbUserUniquenessTable),
					},
				},
			},
		})
		require.NoError(t, err)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			},
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusConflict,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
	})

	t.Run("when error occurred insert user item to table should return error", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			},
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
	})
}

func TestRepository_FindUserWithId(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)

		now := time.Now().UTC()
		item, err := attributevalue.MarshalMap(&Table{
			Id:        TestUserId,
			Name:      TestUserId,
			Email:     TestEmail,
			Password:  TestPassword,
			Role:      RoleUser,
			CreatedAt: now,
		})

		_, err = dynamodbClient.PutItem(
			ctx,
			&dynamodb.PutItemInput{
				Item:      item,
				TableName: aws.String(TestDynamoDbUserTable),
			},
		)
		require.NoError(t, err)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, err := repository.FindUserWithId(
			ctx,
			TestUserId,
		)

		assert.Equal(t, &Table{
			Id:        TestUserId,
			Name:      TestUserId,
			Email:     TestEmail,
			Password:  TestPassword,
			Role:      RoleUser,
			CreatedAt: now,
		}, user)
		assert.NoError(t, err)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = aws.String("localhost:8989")
			options.Region = TestAwsRegion
		})

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, cerr := repository.FindUserWithId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user not found in table should return error", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, cerr := repository.FindUserWithId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_FindUserWithEmail(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)

		now := time.Now().UTC()
		item, err := attributevalue.MarshalMap(&Table{
			Id:        TestUserId,
			Name:      TestUserId,
			Email:     TestEmail,
			Password:  TestPassword,
			Role:      RoleUser,
			CreatedAt: now,
		})

		_, err = dynamodbClient.PutItem(
			ctx,
			&dynamodb.PutItemInput{
				Item:      item,
				TableName: aws.String(TestDynamoDbUserTable),
			},
		)
		require.NoError(t, err)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, err := repository.FindUserWithEmail(
			ctx,
			TestEmail,
		)

		assert.Equal(t, &Table{
			Id:        TestUserId,
			Name:      TestUserId,
			Email:     TestEmail,
			Password:  TestPassword,
			Role:      RoleUser,
			CreatedAt: now,
		}, user)
		assert.NoError(t, err)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = aws.String("localhost:8989")
			options.Region = TestAwsRegion
		})

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, cerr := repository.FindUserWithEmail(
			ctx,
			TestEmail,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user not found should return error", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createUserTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		})
		user, cerr := repository.FindUserWithEmail(
			ctx,
			TestEmail,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_InsertRefreshTokenHistory(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createRefreshTokenHistoryTable(t, ctx, dynamodbClient)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
				},
			},
		)

		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
			Id:        "abcd-abcd-abcd-abcd",
			UserID:    "abcd-abcd-abcd-abcd",
			Token:     "abcd.abcd.abcd",
			ExpiresAt: time.Now().UTC(),
		})

		assert.NoError(t, err)
	})

	t.Run("when error occurred while insert user item should return error", func(t *testing.T) {
		ctx := context.Background()

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = aws.String("uri")
			options.Region = TestAwsRegion
		})

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
				},
			},
		)

		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
			Id:        "abcd-abcd-abcd-abcd",
			UserID:    "abcd-abcd-abcd-abcd",
			Token:     "abcd.abcd.abcd",
			ExpiresAt: time.Now().UTC(),
		})

		assert.Error(t, err)
	})
}

func TestRepository_FindRefreshTokenWithUserId(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createRefreshTokenHistoryTable(t, ctx, dynamodbClient)

		now := time.Now().UTC().Add(10 * time.Minute)
		item, err := attributevalue.MarshalMap(&RefreshTokenHistoryTable{
			Id:        TestRefreshTokenHistoryItemId,
			UserID:    TestUserId,
			Token:     TestAccessToken,
			ExpiresAt: now,
		})

		_, err = dynamodbClient.PutItem(
			ctx,
			&dynamodb.PutItemInput{
				Item:      item,
				TableName: aws.String(TestDynamoDbRefreshTokenHistoryTable),
			},
		)
		require.NoError(t, err)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
			},
		})
		user, cerr := repository.FindRefreshTokenWithUserId(
			ctx,
			TestUserId,
		)

		assert.Equal(t, &RefreshTokenHistoryTable{
			Id:        TestRefreshTokenHistoryItemId,
			UserID:    TestUserId,
			Token:     TestAccessToken,
			ExpiresAt: now,
		}, user)
		assert.NoError(t, cerr)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = aws.String("localhost:8989")
			options.Region = TestAwsRegion
		})

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
			},
		})
		user, cerr := repository.FindRefreshTokenWithUserId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when refresh token not found should return error", func(t *testing.T) {
		ctx := context.Background()

		container, uri := setupDynamoDbContainer(t, ctx)
		defer container.Terminate(ctx)

		cfg, err := awsCfg.LoadDefaultConfig(ctx)
		require.NoError(t, err)

		dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = uri
			options.Region = TestAwsRegion
		})
		createRefreshTokenHistoryTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
			},
		})
		user, cerr := repository.FindRefreshTokenWithUserId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_UpdateUserById(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("with email", func(t *testing.T) {
			ctx := context.Background()

			container, uri := setupDynamoDbContainer(t, ctx)
			defer container.Terminate(ctx)

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = uri
				options.Region = TestAwsRegion
			})
			createUserTable(t, ctx, dynamodbClient)
			createUserUniquenessTable(t, ctx, dynamodbClient)

			fakeUserItem, err := attributevalue.MarshalMap(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
			require.NoError(t, err)

			fakeUserUniquenessItem, err := attributevalue.MarshalMap(&UniquenessTable{
				Unique: TestEmail,
				Type:   UniquenessEmail,
			})
			require.NoError(t, err)

			_, err = dynamodbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
				TransactItems: []types.TransactWriteItem{
					{
						Put: &types.Put{
							Item:      fakeUserItem,
							TableName: aws.String(TestDynamoDbUserTable),
						},
					},
					{
						Put: &types.Put{
							Item:      fakeUserUniquenessItem,
							TableName: aws.String(TestDynamoDbUserUniquenessTable),
						},
					},
				},
			})
			require.NoError(t, err)

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Email:    "new-test@test.com",
					Password: TestPassword,
				},
			)

			assert.NoError(t, cerr)
		})

		t.Run("without email", func(t *testing.T) {
			ctx := context.Background()

			container, uri := setupDynamoDbContainer(t, ctx)
			defer container.Terminate(ctx)

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = uri
				options.Region = TestAwsRegion
			})
			createUserTable(t, ctx, dynamodbClient)
			createUserUniquenessTable(t, ctx, dynamodbClient)

			fakeUserItem, err := attributevalue.MarshalMap(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
			require.NoError(t, err)

			fakeUserUniquenessItem, err := attributevalue.MarshalMap(&UniquenessTable{
				Unique: TestEmail,
				Type:   UniquenessEmail,
			})
			require.NoError(t, err)

			_, err = dynamodbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
				TransactItems: []types.TransactWriteItem{
					{
						Put: &types.Put{
							Item:      fakeUserItem,
							TableName: aws.String(TestDynamoDbUserTable),
						},
					},
					{
						Put: &types.Put{
							Item:      fakeUserUniquenessItem,
							TableName: aws.String(TestDynamoDbUserUniquenessTable),
						},
					},
				},
			})
			require.NoError(t, err)

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Password: TestPassword,
				},
			)

			assert.NoError(t, cerr)
		})
	})

	t.Run("with email field error cases", func(t *testing.T) {
		t.Run("when error occurred while find user should return error", func(t *testing.T) {
			ctx := context.Background()

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = aws.String("localhost:8989")
				options.Region = TestAwsRegion
			})

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Email:    "new-test@test.com",
					Password: TestPassword,
				},
			)

			assert.Error(t, cerr)
			assert.Equal(t,
				http.StatusInternalServerError,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
		})

		t.Run("when user not found should return error", func(t *testing.T) {
			ctx := context.Background()

			container, uri := setupDynamoDbContainer(t, ctx)
			defer container.Terminate(ctx)

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = uri
				options.Region = TestAwsRegion
			})
			createUserTable(t, ctx, dynamodbClient)

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Email:    "new-test@test.com",
					Password: TestPassword,
				},
			)

			assert.Error(t, cerr)
			assert.Equal(t,
				http.StatusNotFound,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
		})

		t.Run("when error occurred while update user should return error", func(t *testing.T) {
			ctx := context.Background()

			container, uri := setupDynamoDbContainer(t, ctx)
			defer container.Terminate(ctx)

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = uri
				options.Region = TestAwsRegion
			})
			createUserTable(t, ctx, dynamodbClient)

			fakeUserItem, err := attributevalue.MarshalMap(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
			require.NoError(t, err)

			_, err = dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
				Item:      fakeUserItem,
				TableName: aws.String(TestDynamoDbUserTable),
			})
			require.NoError(t, err)

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Email:    "new-test@test.com",
					Password: TestPassword,
				},
			)

			assert.Error(t, cerr)
			assert.Equal(t,
				http.StatusInternalServerError,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
		})
	})

	t.Run("without email field error cases", func(t *testing.T) {
		t.Run("error occurred while update user without email field should return error", func(t *testing.T) {
			ctx := context.Background()

			cfg, err := awsCfg.LoadDefaultConfig(ctx)
			require.NoError(t, err)

			dynamodbClient := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
				options.BaseEndpoint = aws.String("localhost:8989")
				options.Region = TestAwsRegion
			})

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			})

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Password: TestPassword,
				},
			)

			assert.Error(t, cerr)
			assert.Equal(t,
				http.StatusInternalServerError,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
		})
	})
}

func createRefreshTokenHistoryTable(t *testing.T, ctx context.Context, dynamodbClient *dynamodb.Client) {
	_, err := dynamodbClient.CreateTable(ctx, &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
		TableName: aws.String(TestDynamoDbRefreshTokenHistoryTable),
	})
	require.NoError(t, err)
}

func createUserTable(t *testing.T, ctx context.Context, dynamodbClient *dynamodb.Client) {
	_, err := dynamodbClient.CreateTable(ctx, &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
		TableName: aws.String(TestDynamoDbUserTable),
	})
	require.NoError(t, err)
}

func createUserUniquenessTable(t *testing.T, ctx context.Context, dynamodbClient *dynamodb.Client) {
	_, err := dynamodbClient.CreateTable(ctx, &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("unique"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("unique"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
		TableName: aws.String(TestDynamoDbUserUniquenessTable),
	})
	require.NoError(t, err)
}

func setupDynamoDbContainer(t *testing.T, ctx context.Context) (testcontainers.Container, *string) {
	req := testcontainers.ContainerRequest{
		Image:        "amazon/dynamodb-local",
		ExposedPorts: []string{"8000/tcp"},
		WaitingFor:   wait.NewHostPortStrategy("8000"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "8000")
	require.NoError(t, err)

	return container, aws.String(fmt.Sprintf("http://%s:%s", ip, port))
}
