//go:build unit

package user

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
	"user-api/pkg/jwt_generator"
)

var (
	TestPrivateKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPaQZM9NX2H8lG9f+8MZ2eRSlqGsnj2yZMtfBYecCMmpoAoGCCqGSM49
AwEHoUQDQgAEHCnaSv1W3JI8jd+CkIZN1AUxldYWEYx9LACT245DA8dJJMx5TXP1
wtoFwCBLAORaw/fHr0X8MHUEstfqh3cTTg==
-----END EC PRIVATE KEY-----`)
	TestPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCnaSv1W3JI8jd+CkIZN1AUxldYW
EYx9LACT245DA8dJJMx5TXP1wtoFwCBLAORaw/fHr0X8MHUEstfqh3cTTg==
-----END PUBLIC KEY-----`)
)

var TestJwtClaims = &jwt_generator.Claims{
	Name:  TestUserName,
	Email: TestEmail,
	Role:  RoleUser,
	RegisteredClaims: jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    jwt_generator.IssuerDefault,
		Subject:   TestUserId,
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
	},
}

const (
	TestUserId                        = "abcd-abcd-abcd-abcd-abcd"
	TestCryptPassword                 = "$2a$07$21Py6b8E1XWLlpSS1ASxK.RhNpvm1n3q34G9uqysCwx/ciP0vSaEm\n"
	TestRefreshTokenHistoryDocumentId = "abcd-abcd-abcd-abcd"
	TestRefreshToken                  = "abcd.abcd.abcd"
	TestAccessToken                   = "abcd.abcd.abcd"
)

func TestNewService(t *testing.T) {
	userService := NewService(nil, nil)

	assert.Implements(t, (*Service)(nil), userService)
}

func TestService_Register(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		tokens, err := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(
				"",
				errors.New("something went wrong"),
			)

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return(TestAccessToken, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateRefreshToken(gomock.Any(), TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while insert refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(errors.New("something went wrong"))

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		_, err = userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})
}

func TestService_Login(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Document{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Role:     RoleUser,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		tokens, err := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(nil, cerror.NewError(http.StatusNotFound, "not found"))

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while compare password should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Document{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: "different-password",
				Role:     RoleUser,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Document{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Role:     RoleUser,
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Document{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Role:     RoleUser,
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return(TestAccessToken, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateRefreshToken(gomock.Any(), TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Document{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Role:     RoleUser,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(errors.New("something went wrong"))

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		_, err = userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})
}

func TestService_UpdateUserById(t *testing.T) {
	TestUpdateUserPayload := &UpdateUserPayload{
		Name:     TestUserName,
		Email:    TestEmail,
		Password: TestPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(gomock.Any(), gomock.Any()).
			Return(nil)

		jwtGenerator, _ := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		ctx := context.Background()
		service := NewService(mockUserRepository, jwtGenerator)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens)
	})

	t.Run("when error occurred while update user by id should return error", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(errors.New("update user error"))

		ctx := context.Background()
		service := NewService(mockUserRepository, nil)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while find user by id should return error", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(nil, errors.New("user not found"))

		ctx := context.Background()
		service := NewService(mockUserRepository, nil)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("generate access token error"))

		ctx := context.Background()
		service := NewService(mockUserRepository, mockJwtGenerator)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while generate refresh token should return error", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("abcd.abcd.abcd", nil)
		mockJwtGenerator.
			EXPECT().
			GenerateRefreshToken(gomock.Any(), TestUserId).
			Return("", errors.New("generate refresh token error"))

		ctx := context.Background()
		service := NewService(mockUserRepository, mockJwtGenerator)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while insert refresh token with user id should return error", func(t *testing.T) {
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(gomock.Any(), gomock.Any()).
			Return(errors.New("insert refresh token error"))

		jwtGenerator, _ := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		ctx := context.Background()
		service := NewService(mockUserRepository, jwtGenerator)
		tokens, err := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})
}

func TestService_GetAccessTokenByRefreshToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			}, nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})

	t.Run("when error occurred while find refresh token with user id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(nil, errors.New("something went wrong"))

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("if refresh token its not same should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     "wrong-refresh-token",
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("if refresh token expires should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("when error occurred while find user with id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(nil, errors.New("something went wrong"))

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("when error occurred generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		accessToken, err := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})
}

func TestService_VerifyAccessToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpireAt := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpireAt, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(accessToken).
			Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			}, nil)

		ctx := context.Background()
		service := NewService(mockUserRepository, mockJwtGenerator)

		var jwtClaims *jwt_generator.Claims
		jwtClaims, err = service.VerifyAccessToken(ctx, accessToken)

		assert.NoError(t, err)
		assert.Equal(t, TestJwtClaims, jwtClaims)
	})

	t.Run("when jwt is not valid should return error", func(t *testing.T) {
		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpiresAt := time.Now().UTC().Add(10 * -time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpiresAt, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(accessToken).
			Return(nil, cerror.NewError(
				http.StatusUnauthorized,
				"expired jwt token",
			).SetSeverity(zapcore.WarnLevel))

		ctx := context.Background()
		service := NewService(nil, mockJwtGenerator)

		var jwtClaims *jwt_generator.Claims
		jwtClaims, err = service.VerifyAccessToken(ctx, accessToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})

	t.Run("when user can't find by user id should return error", func(t *testing.T) {
		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpireAt := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpireAt, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(accessToken).
			Return(&jwt_generator.Claims{
				Name:  TestUserName,
				Email: TestEmail,
				Role:  RoleUser,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    jwt_generator.IssuerDefault,
					Subject:   TestUserId,
					ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(10 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				},
			}, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(nil, cerror.NewError(
				http.StatusNotFound,
				"user not found",
			).SetSeverity(zapcore.WarnLevel))

		ctx := context.Background()
		service := NewService(mockUserRepository, mockJwtGenerator)

		var jwtClaims *jwt_generator.Claims
		jwtClaims, err = service.VerifyAccessToken(ctx, accessToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})

	t.Run("when error occurred find user by user id should return error", func(t *testing.T) {
		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpireAt := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpireAt, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(accessToken).
			Return(&jwt_generator.Claims{
				Name:  TestUserName,
				Email: TestEmail,
				Role:  RoleUser,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    jwt_generator.IssuerDefault,
					Subject:   TestUserId,
					ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(10 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				},
			}, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), TestUserId).
			Return(nil, cerror.NewError(
				http.StatusInternalServerError,
				"error",
			))

		ctx := context.Background()
		service := NewService(mockUserRepository, mockJwtGenerator)

		var jwtClaims *jwt_generator.Claims
		jwtClaims, err = service.VerifyAccessToken(ctx, accessToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})
}
