package user

import (
	"context"

	"user-api/pkg/cerror"
	"user-api/pkg/config"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Repository interface {
	InsertUser(ctx context.Context, user *UserDocument) (string, error)
	FindUserWithId(ctx context.Context, userId string) (*UserDocument, error)
	FindUserWithEmail(ctx context.Context, email string) (*UserDocument, error)
	FindUserWithName(ctx context.Context, name string) (*UserDocument, error)
	InsertRefreshTokenHistory(ctx context.Context, refreshTokenHistory *RefreshTokenHistoryDocument) error
	FindRefreshTokenWithUserId(ctx context.Context, userId string) (*RefreshTokenHistoryDocument, error)
}

type repository struct {
	mongoClient *mongo.Client
	config      *config.Config
}

func NewRepository(
	mongoClient *mongo.Client,
	config *config.Config,
) Repository {
	return &repository{
		mongoClient: mongoClient,
		config:      config,
	}
}

func (r *repository) InsertUser(ctx context.Context, user *UserDocument) (string, error) {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongodbUserCollection])

	var foundUser *UserDocument

	filter := bson.D{{"$or", bson.A{
		bson.D{{"email", user.Email}},
		bson.D{{"name", user.Name}},
	}}}
	err := collection.FindOne(ctx, &filter).Decode(&foundUser)
	if err != nil && err != mongo.ErrNoDocuments {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while user existing check",
			zap.Error(err),
		)
	}

	if foundUser != nil {
		return "", cerror.NewError(
			fiber.StatusConflict,
			"user already exists",
		).SetSeverity(zapcore.WarnLevel)
	}

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while insert user",
			zap.Error(err),
		)
	}

	userID, ok := result.InsertedID.(string)
	if !ok {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while type casting for user id",
		)
	}

	return userID, nil
}

func (r *repository) InsertRefreshTokenHistory(
	ctx context.Context,
	refreshTokenHistory *RefreshTokenHistoryDocument,
) error {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongoDbRefreshTokenHistoryCollection])

	_, err := collection.InsertOne(ctx, refreshTokenHistory)
	if err != nil {
		return cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while insert refresh token",
			zap.Error(err),
		)
	}

	return nil
}

func (r *repository) FindUserWithEmail(ctx context.Context, email string) (*UserDocument, error) {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongodbUserCollection])

	var user *UserDocument

	filter := bson.D{{"email", email}}
	err := collection.FindOne(ctx, &filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.NewError(
				fiber.StatusNotFound,
				"user not found",
			).SetSeverity(zapcore.WarnLevel)
		}

		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while find user with email",
			zap.Error(err),
		)
	}

	return user, nil
}

func (r *repository) FindUserWithName(ctx context.Context, name string) (*UserDocument, error) {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongodbUserCollection])

	var user *UserDocument

	filter := bson.D{{"name", name}}
	err := collection.FindOne(ctx, &filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.NewError(
				fiber.StatusNotFound,
				"user not found",
			).SetSeverity(zapcore.WarnLevel)
		}

		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while find user with name",
			zap.Error(err),
		)
	}

	return user, nil
}

func (r *repository) FindUserWithId(ctx context.Context, userId string) (*UserDocument, error) {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongodbUserCollection])

	var user *UserDocument

	filter := bson.D{{"_id", userId}}
	err := collection.FindOne(ctx, &filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.NewError(
				fiber.StatusNotFound,
				"user not found",
			).SetSeverity(zapcore.WarnLevel)
		}

		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while find user with id",
			zap.Error(err),
		)
	}

	return user, nil
}

func (r *repository) FindRefreshTokenWithUserId(
	ctx context.Context, userId string,
) (*RefreshTokenHistoryDocument, error) {
	collection := r.mongoClient.
		Database(r.config.Mongodb.Database).
		Collection(r.config.Mongodb.Collections[config.MongoDbRefreshTokenHistoryCollection])

	var refreshToken *RefreshTokenHistoryDocument

	filter := bson.D{{"userId", userId}}
	findOneOptions := options.FindOne().SetSort(bson.M{"$natural": -1})
	err := collection.FindOne(ctx, &filter, findOneOptions).Decode(&refreshToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, cerror.NewError(
				fiber.StatusNotFound,
				"refresh token not found",
			).SetSeverity(zapcore.WarnLevel)
		}

		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while find refresh token",
			zap.Error(err),
		)
	}

	return refreshToken, nil
}
