package user

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"user-service/pkg/cerror"
	"user-service/pkg/jwt_generator"
)

type Service interface {
	Register(
		ctx context.Context,
		user *RegisterPayload,
	) (*jwt_generator.Tokens, *cerror.CustomError)
	Login(
		ctx context.Context,
		user *LoginPayload,
	) (*jwt_generator.Tokens, *cerror.CustomError)
	UpdateUserById(
		ctx context.Context,
		userId string,
		user *UpdateUserPayload,
	) (*jwt_generator.Tokens, *cerror.CustomError)
	GetAccessTokenByRefreshToken(
		ctx context.Context,
		userId string,
		refreshToken string,
	) (*AccessTokenPayload, *cerror.CustomError)
}

type service struct {
	repository   Repository
	jwtGenerator jwt_generator.JwtGenerator
}

func NewService(
	repository Repository,
	jwtGenerator jwt_generator.JwtGenerator,
) Service {
	return &service{
		repository:   repository,
		jwtGenerator: jwtGenerator,
	}
}

func (s *service) Register(ctx context.Context, user *RegisterPayload) (*jwt_generator.Tokens, *cerror.CustomError) {
	var err error

	var hashedPassword []byte
	hashedPassword, err = bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while generate hash from password",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	userId := uuid.NewString()
	customError := s.repository.InsertUser(ctx, &Table{
		ID:        userId,
		Name:      user.Name,
		Email:     user.Email,
		Password:  string(hashedPassword),
		Plan:      PlanDefault,
		CreatedAt: time.Now().UTC(),
	})
	if customError != nil {
		return nil, customError
	}

	var accessToken string
	accessToken, err = s.jwtGenerator.GenerateAccessToken(
		jwt_generator.AccessTokenExpirationDuration,
		user.Name,
		user.Email,
		userId,
	)
	if err != nil {
		customError := cerror.ErrorGenerateAccessToken
		customError.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, customError
	}

	var refreshToken string
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(jwt_generator.RefreshTokenExpirationDuration, userId)
	if err != nil {
		customError := cerror.ErrorGenerateRefreshToken
		customError.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, customError
	}

	refreshTokenId := uuid.NewString()
	refreshTokenExpiresAt := time.Now().UTC().Add(jwt_generator.RefreshTokenExpirationDuration)
	customError = s.repository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
		ID:        refreshTokenId,
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
		UserID:    userId,
	})
	if customError != nil {
		return nil, customError
	}

	identityVerificationHistoryId := uuid.NewString()
	verificationCode := uuid.NewString()
	identityVerificationExpiresAt := time.Now().UTC().Add(jwt_generator.IdentityVerificationExpirationDuration)
	customError = s.repository.InsertIdentityVerificationHistory(ctx, &IdentityVerificationTable{
		ID:        identityVerificationHistoryId,
		UserID:    userId,
		Type:      IdentityEmail,
		Code:      verificationCode,
		ExpiresAt: identityVerificationExpiresAt,
	})
	if customError != nil {
		return nil, customError
	}

	customError = s.repository.SendEmailVerificationMessage(ctx, &EmailVerificationSqsMessageBody{
		Email:            user.Email,
		VerificationCode: verificationCode,
	})
	if customError != nil {
		return nil, customError
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
	*cerror.CustomError,
) {
	user, customError := s.repository.FindUserWithEmail(ctx, claimedUser.Email)
	if customError != nil {
		statusCode := customError.HttpStatusCode
		if statusCode == http.StatusNotFound {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusUnauthorized,
				LogMessage:     "user credentials invalid",
				LogSeverity:    zap.WarnLevel,
			}
		}
		return nil, customError
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(claimedUser.Password))
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusUnauthorized,
			LogMessage:     "error occurred while compare passwords",
			LogSeverity:    zap.WarnLevel,
		}
	}

	var accessToken string
	accessToken, err = s.jwtGenerator.GenerateAccessToken(
		jwt_generator.AccessTokenExpirationDuration,
		user.Name,
		user.Email,
		user.ID,
	)
	if err != nil {
		customError = cerror.ErrorGenerateAccessToken
		customError.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, customError
	}

	var refreshToken string
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(jwt_generator.RefreshTokenExpirationDuration, user.ID)
	if err != nil {
		customError = cerror.ErrorGenerateRefreshToken
		customError.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, customError
	}

	refreshTokenExpiresAt := time.Now().UTC().Add(jwt_generator.RefreshTokenExpirationDuration)
	customError = s.repository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
		ID:        uuid.New().String(),
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
		UserID:    user.ID,
	})
	if customError != nil {
		return nil, customError
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
) (*jwt_generator.Tokens, *cerror.CustomError) {
	user, customError := s.repository.FindUserWithId(ctx, userId)
	if customError != nil {
		return nil, customError
	}

	if user.Email == updateUser.Email {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusConflict,
			LogMessage:     "email already belongs to this user",
			LogSeverity:    zap.WarnLevel,
		}
	}

	if updateUser.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateUser.Password), bcrypt.DefaultCost)
		if err != nil {
			isErrPasswordTooLong := errors.Is(err, bcrypt.ErrPasswordTooLong)
			if isErrPasswordTooLong {
				return nil, &cerror.CustomError{
					HttpStatusCode: http.StatusBadRequest,
					LogMessage:     "password length bigger than 72 length",
					LogSeverity:    zap.WarnLevel,
				}
			}

			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while generate hash from password",
				LogSeverity:    zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}
		updateUser.Password = string(hashedPassword)
	}

	customError = s.repository.UpdateUserById(ctx, userId, updateUser)
	if customError != nil {
		return nil, customError
	}

	userName := user.Name
	if updateUser.Name != "" {
		userName = updateUser.Name
	}

	userEmail := user.Email
	if updateUser.Email != "" {
		userEmail = updateUser.Email
	}

	accessToken, err := s.jwtGenerator.GenerateAccessToken(
		jwt_generator.AccessTokenExpirationDuration,
		userName,
		userEmail,
		userId,
	)
	if err != nil {
		customError = cerror.ErrorGenerateAccessToken
		customError.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, customError
	}

	var refreshToken string
	refreshToken, err = s.jwtGenerator.GenerateRefreshToken(jwt_generator.RefreshTokenExpirationDuration, user.ID)
	if err != nil {
		cerr := cerror.ErrorGenerateRefreshToken
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	refreshTokenExpiresAt := time.Now().UTC().Add(jwt_generator.RefreshTokenExpirationDuration)
	customError = s.repository.InsertRefreshTokenHistory(ctx, &RefreshTokenHistoryTable{
		ID:        uuid.NewString(),
		UserID:    userId,
		Token:     refreshToken,
		ExpiresAt: refreshTokenExpiresAt,
	})
	if customError != nil {
		return nil, customError
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
	*cerror.CustomError,
) {
	refreshTokenClaims, err := s.jwtGenerator.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusForbidden,
			LogMessage:     "ambiguous refresh token",
			LogSeverity:    zap.WarnLevel,
		}
	}

	var (
		tokenCreatedAt = refreshTokenClaims.IssuedAt.Time
		tokenExpiresAt = refreshTokenClaims.ExpiresAt.Time
	)
	refreshTokenDocument, customError := s.repository.FindRefreshTokenByUserId(
		ctx,
		userId,
		refreshToken,
		tokenCreatedAt,
		tokenExpiresAt,
	)
	if customError != nil {
		return nil, customError
	}

	if refreshTokenDocument.Token != refreshToken {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusForbidden,
			LogMessage:     "invalid refresh token",
			LogSeverity:    zap.WarnLevel,
		}
	}

	now := time.Now().UTC()
	refreshTokenExpire := refreshTokenDocument.ExpiresAt.After(now)
	if !refreshTokenExpire {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusForbidden,
			LogMessage:     "refresh token expired",
			LogSeverity:    zap.WarnLevel,
		}
	}

	var user *Table
	user, customError = s.repository.FindUserWithId(ctx, userId)
	if customError != nil {
		return nil, customError
	}

	accessToken, err := s.jwtGenerator.GenerateAccessToken(
		jwt_generator.AccessTokenExpirationDuration,
		user.Name,
		user.Email,
		user.ID,
	)
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
