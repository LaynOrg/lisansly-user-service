package user

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

type Repository interface {
	InsertUser(ctx context.Context, user *Document) (string, error)
	FindUserWithId(ctx context.Context, userId string) (*Document, error)
	FindUserWithEmail(ctx context.Context, email string) (*Document, error)
	InsertRefreshTokenHistory(ctx context.Context, refreshTokenHistory *RefreshTokenHistoryDocument) error
	FindRefreshTokenWithUserId(ctx context.Context, userId string) (*RefreshTokenHistoryDocument, error)
	UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) error
}

type repository struct {
	mongoClient   *mongo.Client
	mongoDbConfig *config.MongodbConfig
}

func NewRepository(
	mongoClient *mongo.Client,
	mongoDbConfig *config.MongodbConfig,
) Repository {
	return &repository{
		mongoClient:   mongoClient,
		mongoDbConfig: mongoDbConfig,
	}
}

func (r *repository) InsertUser(ctx context.Context, user *Document) (string, error) {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongodbUserCollection])

	var foundUser *Document

	filter := bson.D{{"email", user.Email}}
	err := collection.FindOne(ctx, &filter).Decode(&foundUser)
	if err != nil && err != mongo.ErrNoDocuments {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while user existing check",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	if foundUser != nil {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusConflict,
			LogMessage:     "user already exists",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while insert user",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	userID, ok := result.InsertedID.(string)
	if !ok {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while type casting for user id",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	return userID, nil
}

func (r *repository) InsertRefreshTokenHistory(
	ctx context.Context,
	refreshTokenHistory *RefreshTokenHistoryDocument,
) error {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongoDbRefreshTokenHistoryCollection])

	_, err := collection.InsertOne(ctx, refreshTokenHistory)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while insert refresh token",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) FindUserWithEmail(ctx context.Context, email string) (*Document, error) {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongodbUserCollection])

	var user *Document

	filter := bson.D{{"email", email}}
	err := collection.FindOne(ctx, &filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.ErrorNotFound
		}

		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while find user with email",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return user, nil
}

func (r *repository) FindUserWithId(ctx context.Context, userId string) (*Document, error) {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongodbUserCollection])

	var user *Document

	filter := bson.D{{"_id", userId}}
	err := collection.FindOne(ctx, &filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.ErrorNotFound
		}

		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while find user with id",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return user, nil
}

func (r *repository) FindRefreshTokenWithUserId(
	ctx context.Context, userId string,
) (*RefreshTokenHistoryDocument, error) {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongoDbRefreshTokenHistoryCollection])

	var refreshToken *RefreshTokenHistoryDocument

	filter := bson.D{{"userId", userId}}
	findOneOptions := options.FindOne().SetSort(bson.M{"$natural": -1})
	err := collection.FindOne(ctx, &filter, findOneOptions).Decode(&refreshToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusNotFound,
				LogMessage:     "refresh token not found",
				LogSeverity:    zapcore.WarnLevel,
			}
		}

		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while find refresh token",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return refreshToken, nil
}

func (r *repository) UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) error {
	collection := r.mongoClient.
		Database(r.mongoDbConfig.Database).
		Collection(r.mongoDbConfig.Collections[config.MongodbUserCollection])

	userDocument := &Document{
		Name:      user.Name,
		Email:     user.Email,
		Password:  user.Password,
		Role:      RoleUser,
		UpdatedAt: time.Now().UTC(),
	}

	update := bson.D{{"$set", userDocument}}
	updateOptions := options.Update().SetUpsert(false)
	result, err := collection.UpdateByID(ctx, userId, update, updateOptions)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return &cerror.CustomError{
				HttpStatusCode: fiber.StatusConflict,
				LogMessage:     "same email address already exist in user collection",
				LogSeverity:    zapcore.WarnLevel,
			}
		}

		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while update user",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	if result.ModifiedCount == 0 {
		return cerror.ErrorNotFound
	}

	return nil
}
