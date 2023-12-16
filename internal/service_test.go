//go:build unit

package user

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"user-service/pkg/cerror"
	"user-service/pkg/config"
	"user-service/pkg/jwt_generator"
)

const (
	TestUserName                  = "Lynicis"
	TestEmail                     = "test@test.com"
	TestNewEmail                  = "new-email@test.com"
	TestPassword                  = "12345678910"
	TestCryptPassword             = "$2a$07$21Py6b8E1XWLlpSS1ASxK.RhNpvm1n3q34G9uqysCwx/ciP0vSaEm\n"
	TestRefreshTokenHistoryItemId = "abcd-abcd-abcd-abcd"
	TestRefreshToken              = "abcd.abcd.abcd"
	TestAccessToken               = "abcd.abcd.abcd"
)

var (
	TestUserId     = uuid.NewString()
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

func TestNewService(t *testing.T) {
	service := NewService(nil, nil)

	assert.Implements(t, (*Service)(nil), service)
}

func TestService_Register(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mocRepository := NewMockRepository(mockController)
		mocRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertIdentityVerificationHistory(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			SendEmailVerificationMessage(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		service := NewService(mocRepository, jwtGenerator)
		tokens, cerr := service.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Nil(t, cerr)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		userService := NewService(mockUserRepository, nil)
		tokens, cerr := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, gomock.Any()).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockRepository, mockJwtGenerator)
		tokens, cerr := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while generate refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, gomock.Any()).
			Return(TestAccessToken, nil)
		mockJwtGenerator.
			EXPECT().
			GenerateRefreshToken(gomock.Any(), gomock.Any()).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockRepository, mockJwtGenerator)
		tokens, cerr := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while insert refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mockRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockRepository, jwtGenerator)
		tokens, cerr := userService.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while insert identity verification code should return error", func(t *testing.T) {
		ctx := context.Background()
		mocRepository := NewMockRepository(mockController)
		mocRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertIdentityVerificationHistory(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		service := NewService(mocRepository, jwtGenerator)
		tokens, cerr := service.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while send email verification message should return error", func(t *testing.T) {
		ctx := context.Background()
		mocRepository := NewMockRepository(mockController)
		mocRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			InsertIdentityVerificationHistory(ctx, gomock.Any()).
			Return(nil)
		mocRepository.
			EXPECT().
			SendEmailVerificationMessage(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		service := NewService(mocRepository, jwtGenerator)
		tokens, cerr := service.Register(ctx, &RegisterPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, tokens)
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
			Return(&Table{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Plan:     PlanDefault,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		tokens, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Nil(t, cerr)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when user not found should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusNotFound,
				},
			)

		userService := NewService(mockUserRepository, nil)
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.HttpStatusCode,
		)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		userService := NewService(mockUserRepository, nil)
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
	})

	t.Run("when error occurred while compare password should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Table{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: "different-password",
				Plan:     PlanDefault,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.HttpStatusCode,
		)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Table{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Plan:     PlanDefault,
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Table{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Plan:     PlanDefault,
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
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&Table{
				Id:       TestUserId,
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestCryptPassword,
				Plan:     PlanDefault,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		_, cerr := userService.Login(ctx, &LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
	})
}

func TestService_UpdateUserById(t *testing.T) {
	TestUpdateUserPayload := &UpdateUserPayload{
		Name:     TestUserName,
		Email:    TestNewEmail,
		Password: TestPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockUserRepository.
			EXPECT().
			UpdateUserById(ctx, TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, _ := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		service := NewService(mockUserRepository, jwtGenerator)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.Nil(t, cerr)
		assert.NotEmpty(t, tokens)
	})

	t.Run("when error occurred while find user by id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		service := NewService(mockUserRepository, nil)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Empty(t, tokens)
	})

	t.Run("when user want to update email but email want to update same as the database should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)

		jwtGenerator, _ := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		service := NewService(mockUserRepository, jwtGenerator)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusConflict,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when error occurred while update user by id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockUserRepository.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		service := NewService(mockUserRepository, nil)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(ctx, TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestNewEmail, TestUserId).
			Return("", errors.New("generate access token error"))

		service := NewService(mockUserRepository, mockJwtGenerator)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while generate refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(ctx, TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestNewEmail, TestUserId).
			Return("abcd.abcd.abcd", nil)
		mockJwtGenerator.
			EXPECT().
			GenerateRefreshToken(gomock.Any(), TestUserId).
			Return("", errors.New("generate refresh token error"))

		service := NewService(mockUserRepository, mockJwtGenerator)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.HttpStatusCode,
		)
		assert.Empty(t, tokens)
	})

	t.Run("when error occurred while insert refresh token with user id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			UpdateUserById(ctx, TestUserId, TestUpdateUserPayload).
			Return(nil)
		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC().Add(-24 * time.Hour),
				UpdatedAt: time.Now().UTC(),
			}, nil)
		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		jwtGenerator, _ := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})

		service := NewService(mockUserRepository, jwtGenerator)
		tokens, cerr := service.UpdateUserById(ctx, TestUserId, TestUpdateUserPayload)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
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
			Return(&RefreshTokenHistoryTable{
				Id:        TestRefreshTokenHistoryItemId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC(),
			}, nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator(&config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.Nil(t, cerr)
		assert.NotEmpty(t, accessToken.Token)
	})

	t.Run("when error occurred while find refresh token with user id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		userService := NewService(mockUserRepository, nil)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, accessToken)
	})

	t.Run("when refresh token is not same should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryTable{
				Id:        TestRefreshTokenHistoryItemId,
				Token:     "wrong-refresh-token",
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusForbidden,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, accessToken)
	})

	t.Run("when refresh token expired should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryTable{
				Id:        TestRefreshTokenHistoryItemId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			http.StatusForbidden,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, accessToken)
	})

	t.Run("when error occurred while find user with id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryTable{
				Id:        TestRefreshTokenHistoryItemId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			})

		userService := NewService(mockUserRepository, nil)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
			},
			cerr,
		)
		assert.Nil(t, accessToken)
	})

	t.Run("when error occurred generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryTable{
				Id:        TestRefreshTokenHistoryItemId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&Table{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestEmail,
				Password:  TestPassword,
				Plan:      PlanDefault,
				CreatedAt: time.Now().UTC(),
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateAccessToken(gomock.Any(), TestUserName, TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		accessToken, cerr := userService.GetAccessTokenByRefreshToken(ctx, TestUserId, TestRefreshToken)

		assert.NotNil(t, cerr)
		assert.Equal(t,
			cerror.ErrorGenerateAccessToken.HttpStatusCode,
			cerr.HttpStatusCode,
		)
		assert.Nil(t, accessToken)
	})
}
