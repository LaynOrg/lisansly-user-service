package user

import (
	"context"
	"net/http"
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
	GetAccessTokenByRefreshToken(ctx context.Context, userId, refreshToken string) (string, error)
	VerifyAccessToken(ctx context.Context, accessToken string) error
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

	var userId string
	userId, err = s.userRepository.InsertUser(ctx, &Document{
		Id:        uuid.New().String(),
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
	accessTokenExpiresAt := time.Now().UTC().Add(10 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Name, user.Email, userId)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(168 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateToken(refreshTokenExpiresAt, user.Name, user.Email, userId)
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
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(claimedUser.Password))
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusForbidden,
			"error occurred while compare passwords",
		)
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(10 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate",
			zap.Error(err),
		)
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(168 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateToken(refreshTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		return nil, cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate",
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
	accessTokenExpiresAt := time.Now().UTC().Add(10 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		return "", cerror.NewError(
			fiber.StatusInternalServerError,
			"error occurred while generate access token",
			zap.Error(err),
		)
	}

	return accessToken, nil
}

func (s *service) VerifyAccessToken(ctx context.Context, accessToken string) error {
	var err error

	var claims *jwt_generator.Claims
	claims, err = s.jwtGenerator.VerifyToken(accessToken)
	if err != nil {
		return err
	}

	userId := claims.Subject
	_, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		statusCode := err.(cerror.CustomError).Code()
		if statusCode == http.StatusNotFound {
			return cerror.NewError(
				http.StatusUnauthorized,
				"user not found email in jwt claims",
			).SetSeverity(zapcore.WarnLevel)
		}

		return err
	}

	return nil
}
