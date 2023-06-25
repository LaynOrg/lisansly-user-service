//go:build unit

package user

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

const (
	TestMongoDbUserName = "root"
	TestMongoDbPassword = "12345"

	TestMongoDbAmbiguousUri                  = "mongodb://localhost:27017"
	TestMongoDbDatabaseName                  = "lisansly"
	TestMongoDbUserCollection                = "user"
	TestMongoDbRefreshTokenHistoryCollection = "refresh-token-history"
)

func TestNewRepository(t *testing.T) {
	userRepository := NewRepository(nil, config.MongodbConfig{})

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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		userId, err := userRepository.InsertUser(ctx, &Document{
			Id:       TestUserId,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotNil(t, userId)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		credentials := options.Client().
			ApplyURI(TestMongoDbAmbiguousUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(mongoClient, config.MongodbConfig{})

		_, err = userRepository.InsertUser(ctx, &Document{
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: "",
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		_, err = userRepository.InsertUser(ctx, &Document{
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		client, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(client, ctx)

		userRepository := NewRepository(
			client,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
				},
			},
		)

		RefreshTokenExpiresAt := time.Now().UTC().Add(180 * time.Minute)
		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Id:        TestRefreshTokenHistoryDocumentId,
			UserID:    TestUserId,
			Token:     TestRefreshToken,
			ExpiresAt: RefreshTokenExpiresAt,
		})

		assert.NoError(t, err)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		credentials := options.Client().
			ApplyURI(TestMongoDbAmbiguousUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(mongoClient, config.MongodbConfig{})

		RefreshTokenExpiresAt := time.Now().UTC().Add(180 * time.Minute)
		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Id:        TestRefreshTokenHistoryDocumentId,
			UserID:    TestUserId,
			Token:     TestRefreshToken,
			ExpiresAt: RefreshTokenExpiresAt,
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: "",
				Collections: map[string]string{
					config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
				},
			},
		)

		RefreshTokenExpiresAt := time.Now().UTC().Add(180 * time.Minute)
		err = userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
			Id:        TestRefreshTokenHistoryDocumentId,
			UserID:    TestUserId,
			Token:     TestRefreshToken,
			ExpiresAt: RefreshTokenExpiresAt,
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		collection := mongoClient.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbUserCollection)

		_, err = collection.
			InsertOne(ctx, &Document{
				Email:    TestEmail,
				Password: TestPassword,
				Role:     RoleUser,
			})
		require.NoError(t, err)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		user, err := userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.NoError(t, err)
		assert.NotEmpty(t, user)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		credentials := options.Client().
			ApplyURI(TestMongoDbAmbiguousUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(mongoClient, config.MongodbConfig{})

		_, err = userRepository.FindUserWithEmail(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find user in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
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
			InsertOne(ctx, &Document{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestPassword,
				Role:     RoleUser,
			})
		require.NoError(t, err)

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		user, err := userRepository.FindUserWithId(ctx, TestUserId)

		assert.NoError(t, err)
		assert.NotEmpty(t, user)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		credentials := options.Client().
			ApplyURI(TestMongoDbAmbiguousUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(mongoClient, config.MongodbConfig{})

		_, err = userRepository.FindUserWithId(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find user in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
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
				ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
				UserID:    TestUserId,
			})
		require.NoError(t, err)

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
				},
			},
		)

		refreshTokenDocument, err := userRepository.FindRefreshTokenWithUserId(ctx, TestUserId)

		assert.NoError(t, err)
		assert.NotEmpty(t, refreshTokenDocument)
	})

	t.Run("when error occurred while connecting to database should return error", func(t *testing.T) {
		ctx := context.Background()
		credentials := options.Client().
			ApplyURI(TestMongoDbAmbiguousUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(mongoClient, config.MongodbConfig{})

		_, err = userRepository.FindRefreshTokenWithUserId(ctx, TestEmail)

		assert.Error(t, err)
	})

	t.Run("when error occurred find refresh token history in collection but can't find one should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		if err != nil {
			panic(err)
		}
		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			if err != nil {
				panic(err)
			}
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongoDbRefreshTokenHistoryCollection: TestMongoDbRefreshTokenHistoryCollection,
				},
			},
		)

		refreshToken, err := userRepository.FindRefreshTokenWithUserId(ctx, TestEmail)

		assert.Nil(t, refreshToken)
		assert.Error(t, err)
	})
}

func TestRepository_UpdateUserById(t *testing.T) {
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
			InsertOne(ctx, &Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
		require.NoError(t, err)

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		require.NoError(t, err)

		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			require.NoError(t, err)
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		repositoryError := userRepository.UpdateUserById(ctx, TestUserId, &UpdateUserPayload{
			Name:     "UPDATED-NAME",
			Email:    "updatedTest@test.com",
			Password: "updated-test-password",
		})

		var user *Document
		err = client.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbUserCollection).
			FindOne(ctx, bson.D{{"_id", TestUserId}}).
			Decode(&user)
		require.NoError(t, err)

		assert.NoError(t, repositoryError)
		assert.Equal(t, user.Name, "UPDATED-NAME")
		assert.Equal(t, user.Email, "updatedTest@test.com")
		assert.Equal(t, user.Password, "updated-test-password")
	})

	t.Run("when attempt to update email field same email address already exist in collection should return error", func(t *testing.T) {
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

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		collection := client.
			Database(TestMongoDbDatabaseName).
			Collection(TestMongoDbUserCollection)

		_, err = collection.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    bson.M{"email": 1},
			Options: options.Index().SetUnique(true),
		})
		require.NoError(t, err)

		_, err = collection.
			InsertOne(ctx, &Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     "test@test.com",
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
		require.NoError(t, err)

		_, err = collection.
			InsertOne(ctx, &Document{
				Id:        "updateUser",
				Name:      TestUserName,
				Email:     "test2@test.com",
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			})
		require.NoError(t, err)

		err = client.Disconnect(ctx)
		require.NoError(t, err)

		mongoClient, err := mongo.Connect(ctx, credentials)
		require.NoError(t, err)

		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			require.NoError(t, err)
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		repositoryError := userRepository.UpdateUserById(ctx, "updateUser", &UpdateUserPayload{
			Name:     "UPDATED-NAME",
			Email:    "test@test.com",
			Password: "updated-test-password",
		})

		assert.Error(t, repositoryError)
		assert.Equal(t, http.StatusConflict, repositoryError.(*cerror.CustomError).Code)
	})

	t.Run("when attempt to update not exist user should return error", func(t *testing.T) {
		ctx := context.Background()
		container := setupMongoDbContainer(t, ctx)
		mongodbUri, err := container.Endpoint(ctx, "mongodb")
		if err != nil {
			t.Error(fmt.Errorf("failed to get endpoint: %w", err))
		}

		credentials := options.Client().
			ApplyURI(mongodbUri).
			SetAuth(options.Credential{
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
			})

		mongoClient, err := mongo.Connect(ctx, credentials)
		require.NoError(t, err)

		defer func(client *mongo.Client, ctx context.Context) {
			err := client.Disconnect(ctx)
			require.NoError(t, err)
		}(mongoClient, ctx)

		userRepository := NewRepository(
			mongoClient,
			config.MongodbConfig{
				Uri:      mongodbUri,
				Username: TestMongoDbUserName,
				Password: TestMongoDbPassword,
				Database: TestMongoDbDatabaseName,
				Collections: map[string]string{
					config.MongodbUserCollection: TestMongoDbUserCollection,
				},
			},
		)

		repositoryError := userRepository.UpdateUserById(ctx, TestUserId, &UpdateUserPayload{
			Name:     "UPDATED-NAME",
			Email:    "updatedTest@test.com",
			Password: "updated-test-password",
		})

		assert.Error(t, repositoryError)
		assert.Equal(t, http.StatusNotFound, repositoryError.(*cerror.CustomError).Code)
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
