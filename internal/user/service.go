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
	Register(ctx context.Context, user *UserPayload) (*jwt_generator.Tokens, error)
	Login(ctx context.Context, user *UserPayload) (*jwt_generator.Tokens, error)
	GetAccessToken(ctx context.Context, userId, refreshToken string) (string, error)
}

type service struct {
	userRepository Repository
	jwtGenerator   jwt_generator.JwtGenerator
}

func NewService(userRepository Repository, jwtGenerator jwt_generator.JwtGenerator) Service {
	return &service{
		userRepository: userRepository,
		jwtGenerator:   jwtGenerator,
	}
}

func (s *service) Register(ctx context.Context, user *UserPayload) (*jwt_generator.Tokens, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate hash from password",
			zap.Error(err),
		)
	}

	userId, err := s.userRepository.InsertUser(ctx, &UserDocument{
		Id:        uuid.New().String(),
		Email:     user.Email,
		Password:  string(hashedPassword),
		Role:      RoleUser,
		CreatedAt: time.Now().UTC().Unix(),
	})
	if err != nil {
		return nil, err
	}

	accessTokenExpiresAt := time.Now().Add(10 * time.Minute)
	accessToken, err := s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Email, userId)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	refreshTokenExpiresAt := time.Now().Add(168 * time.Hour)
	refreshToken, err := s.jwtGenerator.GenerateToken(refreshTokenExpiresAt, user.Email, userId)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate refresh token",
			zap.Error(err),
		)
	}

	refreshTokenExpiresAtUnix := refreshTokenExpiresAt.UTC().Unix()
	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAtUnix,
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

func (s *service) Login(ctx context.Context, claimedUser *UserPayload) (*jwt_generator.Tokens, error) {
	user, err := s.userRepository.FindUserWithEmail(ctx, claimedUser.Email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(claimedUser.Password))
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while compare passwords",
		)
	}

	accessTokenExpiresAt := time.Now().UTC().Add(10 * time.Minute)
	accessToken, err := s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Email, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate",
			zap.Error(err),
		)
	}

	refreshTokenExpiresAt := time.Now().UTC().Add(168 * time.Hour)
	refreshToken, err := s.jwtGenerator.GenerateToken(refreshTokenExpiresAt, user.Email, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate",
			zap.Error(err),
		)
	}

	refreshTokenExpiresAtUnix := refreshTokenExpiresAt.UTC().Unix()
	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryDocument{
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAtUnix,
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

func (s *service) GetAccessToken(ctx context.Context, userId, refreshToken string) (string, error) {
	refreshTokenDocument, err := s.userRepository.FindRefreshTokenWithUserId(ctx, userId)
	if err != nil {
		return "", err
	}

	if refreshTokenDocument.Token != refreshToken {
		return "", cerror.NewError(
			fiber.StatusForbidden,
			"invalid refresh token",
		).SetSeverity(zapcore.WarnLevel)
	}

	refreshTokenExpiresAt := time.Unix(refreshTokenDocument.ExpiresAt, 0)
	refreshTokenExpire := time.Now().UTC().After(refreshTokenExpiresAt)
	if refreshTokenExpire {
		return "", cerror.NewError(
			fiber.StatusForbidden,
			"refresh token expired",
		).SetSeverity(zapcore.WarnLevel)
	}

	user, err := s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		return "", err
	}

	accessTokenExpiresAt := time.Now().UTC().Add(10 * time.Minute)
	accessToken, err := s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Email, user.Id)
	if err != nil {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	return accessToken, nil
}
