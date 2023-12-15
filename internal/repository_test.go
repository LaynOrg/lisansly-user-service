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
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"user-service/pkg/config"
)

const (
	TestAwsRegion                         = "us-west-1"
	TestDynamoDbUserTable                 = "user"
	TestDynamoDbUserUniquenessTable       = "user-uniqueness"
	TestDynamoDbRefreshTokenHistoryTable  = "refresh-token-history"
	TestDynamoDbIdentityVerificationTable = "identity-verification-history"
	TestEmailVerificationQueueName        = "email-verification"
	TestAwsAccountId                      = "000000000000"
)

func TestNewRepository(t *testing.T) {
	repository := NewRepository(nil, nil, nil, nil)

	assert.Implements(t, (*Repository)(nil), repository)
}

func TestRepository_InsertUser(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)

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
			nil, nil,
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Nil(t, cerr)
	})

	t.Run("when user already exist in table should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)

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
			Type:   IdentityEmail,
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
			nil, nil,
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusConflict,
			cerr.HttpStatusCode,
		)
	})

	t.Run("when error occurred insert user item to table should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			},
			nil, nil,
		)

		cerr := userRepository.InsertUser(ctx, &Table{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
	})
}

func TestRepository_FindUserWithId(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
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
		}, nil, nil)
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
		assert.Nil(t, err)
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
		}, nil, nil)
		user, cerr := repository.FindUserWithId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user not found in table should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
		createUserTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		}, nil, nil)
		user, cerr := repository.FindUserWithId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_FindUserWithEmail(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
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
		}, nil, nil)
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
		assert.Nil(t, err)
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
		}, nil, nil)
		user, cerr := repository.FindUserWithEmail(
			ctx,
			TestEmail,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user not found should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
		createUserTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbUserTable: TestDynamoDbUserTable,
			},
		}, nil, nil)
		user, cerr := repository.FindUserWithEmail(
			ctx,
			TestEmail,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_InsertRefreshTokenHistory(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
		createRefreshTokenHistoryTable(t, ctx, dynamodbClient)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
				},
			}, nil, nil)

		err := userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
			Id:        "abcd-abcd-abcd-abcd",
			UserID:    "abcd-abcd-abcd-abcd",
			Token:     "abcd.abcd.abcd",
			ExpiresAt: time.Now().UTC(),
		})

		assert.Nil(t, err)
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
			}, nil, nil)

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
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
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
		}, nil, nil)
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
		assert.Nil(t, cerr)
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
		}, nil, nil)
		user, cerr := repository.FindRefreshTokenWithUserId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when refresh token not found should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
		createRefreshTokenHistoryTable(t, ctx, dynamodbClient)

		repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
			Tables: map[string]string{
				config.DynamoDbRefreshTokenHistoryTable: TestDynamoDbRefreshTokenHistoryTable,
			},
		}, nil, nil)
		user, cerr := repository.FindRefreshTokenWithUserId(
			ctx,
			TestUserId,
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusNotFound,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_UpdateUserById(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("with email", func(t *testing.T) {
			ctx := context.Background()
			container, dynamodbClient := createDynamoDbClient(t, ctx)
			defer container.Terminate(ctx)
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
				Type:   IdentityEmail,
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
			}, nil, nil)

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Email:    "new-test@test.com",
					Password: TestPassword,
				},
			)

			assert.Nil(t, cerr)
		})

		t.Run("without email", func(t *testing.T) {
			ctx := context.Background()
			container, dynamodbClient := createDynamoDbClient(t, ctx)
			defer container.Terminate(ctx)
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
				Type:   IdentityEmail,
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
			}, nil, nil)

			cerr := repository.UpdateUserById(
				ctx,
				TestUserId,
				&UpdateUserPayload{
					Name:     TestUserName,
					Password: TestPassword,
				},
			)

			assert.Nil(t, cerr)
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
			}, nil, nil)

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
				cerr.HttpStatusCode,
			)
		})

		t.Run("when user not found should return error", func(t *testing.T) {
			ctx := context.Background()
			container, dynamodbClient := createDynamoDbClient(t, ctx)
			defer container.Terminate(ctx)
			createUserTable(t, ctx, dynamodbClient)

			repository := NewRepository(dynamodbClient, &config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbUserTable:           TestDynamoDbUserTable,
					config.DynamoDbUserUniquenessTable: TestDynamoDbUserUniquenessTable,
				},
			}, nil, nil)

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
				cerr.HttpStatusCode,
			)
		})

		t.Run("when error occurred while update user should return error", func(t *testing.T) {
			ctx := context.Background()
			container, dynamodbClient := createDynamoDbClient(t, ctx)
			defer container.Terminate(ctx)
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
			}, nil, nil)

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
				cerr.HttpStatusCode,
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
			}, nil, nil)

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
				cerr.HttpStatusCode,
			)
		})
	})
}

func TestRepository_InsertIdentityVerificationHistory(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)
		createIdentityVerificationTable(t, ctx, dynamodbClient)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbIdentityVerificationHistoryTable: TestDynamoDbIdentityVerificationTable,
				},
			}, nil, nil)

		err := userRepository.InsertIdentityVerificationHistory(ctx, &IdentityVerificationTable{
			Id:        "abcd-abcd-abcd-abcd",
			UserID:    "abcd-abcd-abcd-abcd",
			Type:      IdentityEmail,
			Code:      "abcd.abcd.abcd",
			ExpiresAt: time.Now().UTC(),
		})

		assert.Nil(t, err)
	})

	t.Run("when error occurred insert identity verification history should return error", func(t *testing.T) {
		ctx := context.Background()
		container, dynamodbClient := createDynamoDbClient(t, ctx)
		defer container.Terminate(ctx)

		userRepository := NewRepository(
			dynamodbClient,
			&config.DynamoDbConfig{
				Tables: map[string]string{
					config.DynamoDbIdentityVerificationHistoryTable: TestDynamoDbIdentityVerificationTable,
				},
			}, nil, nil)

		err := userRepository.InsertIdentityVerificationHistory(ctx, &IdentityVerificationTable{
			Id:        "abcd-abcd-abcd-abcd",
			UserID:    "abcd-abcd-abcd-abcd",
			Type:      IdentityEmail,
			Code:      "abcd.abcd.abcd",
			ExpiresAt: time.Now().UTC(),
		})

		assert.NotNil(t, err)
	})
}

func TestRepository_SendEmailVerificationMessage(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container, sqsClient := createSqsClient(t, ctx)
		defer container.Terminate(ctx)
		createEmailVerificationQueueName(t, ctx, sqsClient)

		getQueueUrl, err := sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName:              aws.String(TestEmailVerificationQueueName),
			QueueOwnerAWSAccountId: aws.String(TestAwsAccountId),
		})
		require.NoError(t, err)

		userRepository := NewRepository(nil, nil,
			sqsClient, &config.SQSConfig{
				AwsAccountId:              TestAwsAccountId,
				EmailVerificationQueueUrl: getQueueUrl.QueueUrl,
			},
		)
		cerr := userRepository.SendEmailVerificationMessage(ctx, &EmailVerificationSqsMessageBody{
			Email:            TestEmail,
			VerificationCode: "abcd-abcd-abcd-abcd",
		})

		assert.Nil(t, cerr)
	})

	t.Run("when error occurred while send message to queue should return error", func(t *testing.T) {
		ctx := context.Background()
		container, sqsClient := createSqsClient(t, ctx)
		defer container.Terminate(ctx)

		userRepository := NewRepository(nil, nil,
			sqsClient, &config.SQSConfig{
				AwsAccountId:              TestAwsAccountId,
				EmailVerificationQueueUrl: aws.String(""),
			},
		)
		cerr := userRepository.SendEmailVerificationMessage(ctx, &EmailVerificationSqsMessageBody{
			Email:            TestEmail,
			VerificationCode: "abcd-abcd-abcd-abcd",
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
	})
}

func createEmailVerificationQueueName(t *testing.T, ctx context.Context, sqsClient *sqs.Client) {
	_, err := sqsClient.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String(TestEmailVerificationQueueName),
	})
	require.NoError(t, err)
}

func createIdentityVerificationTable(t *testing.T, ctx context.Context, dynamodbClient *dynamodb.Client) {
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
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
		},
		TableName: aws.String(TestDynamoDbIdentityVerificationTable),
	})
	require.NoError(t, err)
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
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
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
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
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
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
		},
		TableName: aws.String(TestDynamoDbUserUniquenessTable),
	})
	require.NoError(t, err)
}

func createDynamoDbClient(t *testing.T, ctx context.Context) (testcontainers.Container, *dynamodb.Client) {
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "localstack/localstack",
				ExposedPorts: []string{"4566/tcp"},
				Env:          map[string]string{"SERVICES": "dynamodb"},
				WaitingFor:   wait.NewHostPortStrategy("4566"),
			},
			Started: true,
		},
	)
	require.NoError(t, err)

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "4566")
	require.NoError(t, err)

	cfg, err := awsCfg.LoadDefaultConfig(
		ctx,
		awsCfg.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						SigningName:   "aws",
						URL:           fmt.Sprintf("http://%s:%s", ip, port.Port()),
						SigningRegion: TestAwsRegion,
					}, nil
				},
			),
		),
		awsCfg.WithRegion(TestAwsRegion),
		awsCfg.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				"AKID",
				"SECRET_KEY",
				"TOKEN",
			),
		),
	)
	require.NoError(t, err)

	return container, dynamodb.NewFromConfig(cfg)
}

func createSqsClient(t *testing.T, ctx context.Context) (testcontainers.Container, *sqs.Client) {
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "localstack/localstack",
				ExposedPorts: []string{"4566/tcp"},
				Env:          map[string]string{"SERVICES": "sqs"},
				WaitingFor:   wait.NewHostPortStrategy("4566"),
			},
			Started: true,
		},
	)
	require.NoError(t, err)

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "4566")
	require.NoError(t, err)

	cfg, err := awsCfg.LoadDefaultConfig(
		ctx,
		awsCfg.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						SigningName:   "aws",
						URL:           fmt.Sprintf("http://%s:%s", ip, port.Port()),
						SigningRegion: TestAwsRegion,
					}, nil
				},
			),
		),
		awsCfg.WithRegion(TestAwsRegion),
		awsCfg.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				"AKID",
				"SECRET_KEY",
				"TOKEN",
			),
		),
	)
	require.NoError(t, err)

	return container, sqs.NewFromConfig(cfg)
}
