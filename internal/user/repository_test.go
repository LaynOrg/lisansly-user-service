//go:build unit

package user

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"user-api/pkg/config"
)

const (
	TestMongoDbUserName = "root"
	TestMongoDbPassword = "12345"

	TestMongoDbDatabaseName                  = "lisansly"
	TestMongoDbUserCollection                = "user"
	TestMongoDbRefreshTokenHistoryCollection = "refresh-token-history"
)

func TestNewRepository(t *testing.T) {
	userRepository := NewRepository(nil)

	assert.Implements(t, (*Repository)(nil), userRepository)
}

func TestRepository_InsertUser(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		userId, err := userRepository.InsertUser(ctx, &UserDocument{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotNil(t, userId)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		userRepository := NewRepository(&config.Config{})

		_, err := userRepository.InsertUser(ctx, &UserDocument{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred insert user document to collection should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: "",
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		_, err = userRepository.InsertUser(ctx, &UserDocument{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})
}

func TestRepository_InsertRefreshTokenHistory(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
					},
				},
			},
		)

		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Id:     TestRefreshTokenHistoryDocumentId,
			Token:  TestRefreshToken,
			UserID: TestUserId,
		})

		assert.NoError(t, err)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		userRepository := NewRepository(&config.Config{})

		err := userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Token:  TestRefreshToken,
			UserID: TestUserId,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred insert refresh token document to collection should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: "",
					Collections: map[string]string{
						config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
					},
				},
			},
		)

		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Token:  TestRefreshToken,
			UserID: TestUserId,
		})

		assert.Error(t, err)
	})
}

func TestRepository_FindUserWithEmail(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		client, err := mongo.Connect(context.TODO(), options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			}))
		require.NoError(t, err)

		_, err = client.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbUserCollection).
			InsertOne(ctx, &UserDocument{
				Email:    TestEmail,
				Password: TestPassword,
				Role:     RoleUser,
			})
		require.NoError(t, err)

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		user, err := userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.NoError(t, err)
		assert.NotEmpty(t, user)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		userRepository := NewRepository(&config.Config{})

		_, err := userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find user in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		user, err := userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("when error occurred find user in collection should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		_, err = userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.Error(t, err)
	})
}

func TestRepository_FindUserWithUserId(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		client, err := mongo.Connect(context.TODO(), options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			}))
		require.NoError(t, err)

		_, err = client.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbUserCollection).
			InsertOne(ctx, &UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestPassword,
				Role:     RoleUser,
			})
		require.NoError(t, err)

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		user, err := userRepository.FindUserWithId(ctx, TestUserId)

		assert.NoError(t, err)
		assert.NotEmpty(t, user)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		userRepository := NewRepository(&config.Config{})

		_, err := userRepository.FindUserWithId(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find user in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		user, err := userRepository.FindUserWithId(ctx, TestEmail)

		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("when error occurred find user in collection should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongodbUserCollection: TestMongoDbUserCollection,
					},
				},
			},
		)

		_, err = userRepository.FindUserWithId(ctx, TestEmail)

		assert.Error(t, err)
	})
}

func TestRepository_FindRefreshTokenWithUserId(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		client, err := mongo.Connect(context.TODO(), options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			}))
		require.NoError(t, err)

		_, err = client.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbRefreshTokenHistoryCollection).
			InsertOne(ctx, &RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Unix(),
				UserID:    TestUserId,
			})
		require.NoError(t, err)

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
					},
				},
			},
		)

		refreshTokenDocument, err := userRepository.FindRefreshTokenWithUserId(ctx, TestUserId)

		assert.NoError(t, err)
		assert.NotEmpty(t, refreshTokenDocument)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		userRepository := NewRepository(&config.Config{})

		_, err := userRepository.FindRefreshTokenWithUserId(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find refresh token history in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
					},
				},
			},
		)

		refreshToken, err := userRepository.FindRefreshTokenWithUserId(ctx, TestEmail)

		assert.Nil(t, refreshToken)
		assert.Error(t, err)
	})

	t.Run("when error occurred find refresh token history in collection should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		userRepository := NewRepository(
			&config.Config{
				Mongodb: config.MongodbConfig{
					Uri:      mongodbUri,
					Username: TestMongoDbUserName,
					Password: TestMongoDbPassword,
					Database: TestMongoDbDatabaseName,
					Collections: map[string]string{
						config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
					},
				},
			},
		)

		refreshToken, err := userRepository.FindRefreshTokenWithUserId(ctx, TestEmail)

		assert.Nil(t, refreshToken)
		assert.Error(t, err)
	})
}

func setupMongoDbContainer(t *testing.T, ctx context.Context) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image: "mongo",
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": TestMongoDbUserName,
			"MONGO_INITDB_ROOT_PASSWORD": TestMongoDbPassword,
		},
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("Waiting for connections"),
			wait.ForListeningPort("27017/tcp"),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	})

	return container
}
