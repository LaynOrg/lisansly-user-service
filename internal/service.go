package user

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
)

type Service interface {
	Register(ctx context.Context, user *RegisterPayload) (*jwt_generator.Tokens, error)
	Login(ctx context.Context, user *LoginPayload) (*jwt_generator.Tokens, error)
	UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) (*jwt_generator.Tokens, error)
	GetAccessTokenByRefreshToken(ctx context.Context, userId, refreshToken string) (string, error)
	VerifyAccessToken(ctx context.Context, accessToken string) (*jwt_generator.Claims, error)
}

type service struct {
	userRepository Repository
	jwtGenerator   jwt_generator.JwtGenerator
}

func NewService(
	userRepository Repository,
	jwtGenerator jwt_generator.JwtGenerator,
) Service {
	return &service{
		userRepository: userRepository,
		jwtGenerator:   jwtGenerator,
	}
}

func (s *service) Register(ctx context.Context, user *RegisterPayload) (*jwt_generator.Tokens, error) {
	var err error

	var hashedPassword []byte
	hashedPassword, err = bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate hash from password",
			zap.Error(err),
		)
	}

	createdAt := time.Now().UTC()
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while time parsing",
			zap.Error(err),
		)
	}

	userId := uuid.New().String()
	userId, err = s.userRepository.InsertUser(ctx, &Document{
		Id:        userId,
		Name:      user.Name,
		Email:     user.Email,
		Password:  string(hashedPassword),
		Role:      RoleUser,
		CreatedAt: createdAt,
	})
	if err != nil {
		return nil, err
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, userId)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, userId)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate refresh token",
			zap.Error(err),
		)
	}

	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
		Id:        uuid.New().String(),
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
		UserID:    userId,
	})
	if err != nil {
		return nil, err
	}

	return &jwt_generator.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) Login(
	ctx context.Context,
	claimedUser *LoginPayload,
) (
	*jwt_generator.Tokens,
	error,
) {
	var (
		user *Document
		err  error
	)

	user, err = s.userRepository.FindUserWithEmail(ctx, claimedUser.Email)
	if err != nil {
		statusCode := err.(cerror.CustomError).Code()
		if statusCode == fiber.StatusNotFound {
			return nil, cerror.NewError(
				fiber.StatusUnauthorized,
				"user credentials invalid",
			).SetSeverity(zap.WarnLevel)
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(claimedUser.Password))
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusUnauthorized,
			"error occurred while compare passwords",
		)
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate refresh token",
			zap.Error(err),
		)
	}

	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
		Id:        uuid.New().String(),
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
		UserID:    user.Id,
	})
	if err != nil {
		return nil, err
	}

	return &jwt_generator.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) UpdateUserById(
	ctx context.Context,
	userId string,
	updateUser *UpdateUserPayload,
) (*jwt_generator.Tokens, error) {
	var err error

	if updateUser.Password != "" {
		var hashedPassword []byte
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(updateUser.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, cerror.NewError(
				fiber.StatusInternalServerError,
				"error occurred while generate hash from password",
				zap.Error(err),
			)
		}

		updateUser.Password = string(hashedPassword)
	}

	err = s.userRepository.UpdateUserById(ctx, userId, updateUser)
	if err != nil {
		return nil, err
	}

	var user *Document
	user, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		return nil, err
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(
		accessTokenExpiresAt,
		user.Name,
		user.Email,
		userId,
	)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate refresh token",
			zap.Error(err),
		)
	}

	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
		Id:        uuid.New().String(),
		UserID:    userId,
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
	})
	if err != nil {
		return nil, err
	}

	return &jwt_generator.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) GetAccessTokenByRefreshToken(ctx context.Context, userId, refreshToken string) (string, error) {
	var err error

	var refreshTokenDocument *RefreshTokenHistoryDocument
	refreshTokenDocument, err = s.userRepository.FindRefreshTokenWithUserId(ctx, userId)
	if err != nil {
		return "", err
	}

	if refreshTokenDocument.Token != refreshToken {
		return "", cerror.NewError(
			fiber.StatusForbidden,
			"invalid refresh token",
		).SetSeverity(zapcore.WarnLevel)
	}

	refreshTokenExpire := time.Now().UTC().After(refreshTokenDocument.ExpiresAt)
	if refreshTokenExpire {
		return "", cerror.NewError(
			fiber.StatusForbidden,
			"refresh token expired",
		).SetSeverity(zapcore.WarnLevel)
	}

	var user *Document
	user, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		return "", err
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	return accessToken, nil
}

func (s *service) VerifyAccessToken(ctx context.Context, accessToken string) (*jwt_generator.Claims, error) {
	var err error

	var jwtClaims *jwt_generator.Claims
	jwtClaims, err = s.jwtGenerator.VerifyAccessToken(accessToken)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusUnauthorized,
			err.Error(),
		).SetSeverity(zapcore.WarnLevel)
	}

	userId := jwtClaims.Subject
	_, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		statusCode := err.(cerror.CustomError).Code()
		if statusCode == fiber.StatusNotFound {
			return nil, cerror.NewError(
				fiber.StatusUnauthorized,
				"user not found email in jwt claims",
			).SetSeverity(zapcore.WarnLevel)
		}

		return nil, err
	}

	return jwtClaims, nil
}
