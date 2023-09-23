package user

import (
	"context"
	"errors"
	"net/http"
	"time"

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
	GetAccessTokenByRefreshToken(ctx context.Context, userId, refreshToken string) (*AccessTokenPayload, error)
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
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while generate hash from password",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	userId := uuid.NewString()
	err = s.userRepository.InsertUser(context.Background(), &Table{
		Id:        userId,
		Name:      user.Name,
		Email:     user.Email,
		Password:  string(hashedPassword),
		Role:      RoleUser,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, userId)
	if err != nil {
		cerr := cerror.ErrorGenerateAccessToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}

		return nil, cerr
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, userId)
	if err != nil {
		cerr := cerror.ErrorGenerateRefreshToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}

		return nil, cerr
	}

	refreshTokenId := uuid.NewString()
	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
		Id:        refreshTokenId,
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
		user *Table
		err  error
	)

	user, err = s.userRepository.FindUserWithEmail(ctx, claimedUser.Email)
	if err != nil {
		var customError *cerror.CustomError
		ok := errors.As(err, &customError)
		if ok {
			statusCode := customError.HttpStatusCode
			if statusCode == http.StatusNotFound {
				return nil, &cerror.CustomError{
					HttpStatusCode: http.StatusUnauthorized,
					LogMessage:     "user credentials invalid",
					LogSeverity:    zapcore.WarnLevel,
				}
			}
		}

		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(claimedUser.Password))
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusUnauthorized,
			LogMessage:     "error occurred while compare passwords",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		cerr := cerror.ErrorGenerateAccessToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, user.Id)
	if err != nil {
		cerr := cerror.ErrorGenerateRefreshToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
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

	var user *Table
	user, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		return nil, err
	}

	if user.Email == updateUser.Email {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusConflict,
			LogMessage:     "email already belongs to this user",
			LogSeverity:    zap.WarnLevel,
		}
	}

	if updateUser.Password != "" {
		var hashedPassword []byte
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(updateUser.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while generate hash from password",
				LogSeverity:    zapcore.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}
		updateUser.Password = string(hashedPassword)
	}

	err = s.userRepository.UpdateUserById(ctx, userId, updateUser)
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
		cerr := cerror.ErrorGenerateAccessToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var refreshToken string
	refreshTokenExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(refreshTokenExpiresAt, user.Id)
	if err != nil {
		cerr := cerror.ErrorGenerateRefreshToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	err = s.userRepository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
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

func (s *service) GetAccessTokenByRefreshToken(
	ctx context.Context,
	userId string,
	refreshToken string,
) (
	*AccessTokenPayload,
	error,
) {
	var err error

	var refreshTokenDocument *RefreshTokenHistoryTable
	refreshTokenDocument, err = s.userRepository.FindRefreshTokenWithUserId(ctx, userId)
	if err != nil {
		return nil, err
	}

	if refreshTokenDocument.Token != refreshToken {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusForbidden,
			LogMessage:     "invalid refresh token",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	refreshTokenExpire := time.Now().UTC().After(refreshTokenDocument.ExpiresAt)
	if refreshTokenExpire {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusForbidden,
			LogMessage:     "refresh token expired",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	var user *Table
	user, err = s.userRepository.FindUserWithId(ctx, userId)
	if err != nil {
		return nil, err
	}

	var accessToken string
	accessTokenExpiresAt := time.Now().UTC().Add(5 * time.Minute)
	accessToken, err = s.jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, user.Name, user.Email, user.Id)
	if err != nil {
		cerr := cerror.ErrorGenerateAccessToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return &AccessTokenPayload{
		Token: accessToken,
	}, nil
}
