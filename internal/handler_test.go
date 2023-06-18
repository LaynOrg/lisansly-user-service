//go:build unit

package user

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"user-api/pkg/config"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
)

const (
	TestUserName = "Lynicis"
	TestEmail    = "test@test.com"
	TestPassword = "12345678910"

	TestInvalidMail     = "invalid-mail.com"
	TestInvalidPassword = "123"
)

func TestNewHandler(t *testing.T) {
	userHandler := NewHandler(nil)

	assert.Implements(t, (*Handler)(nil), userHandler)
}

func TestHandler_AuthenticationMiddleware(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpireTime := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpireTime, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			VerifyAccessToken(gomock.Any(), accessToken).
			Return(TestJwtClaims, nil)

		handler := NewHandler(mockUserService)
		app.Get("/test", handler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		resp, _ := app.Test(req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("when Authorization header is empty should return error", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		handler := NewHandler(nil)
		app.Get("/test", handler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		resp, _ := app.Test(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("when user service can't validate access token should return error ", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		accessTokenExpireTime := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(accessTokenExpireTime, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			VerifyAccessToken(gomock.Any(), accessToken).
			Return(
				nil,
				cerror.NewError(
					http.StatusUnauthorized,
					"access token is not valid",
				),
			)

		handler := NewHandler(mockUserService)
		app.Get("/test", handler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		resp, _ := app.Test(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestHandler_Register(t *testing.T) {
	TestUserModel := RegisterPayload{
		Name:     TestUserName,
		Email:    TestEmail,
		Password: TestPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().Register(gomock.Any(), &TestUserModel).Return(&jwt_generator.Tokens{
			AccessToken:  TestAccessToken,
			RefreshToken: TestRefreshToken,
		}, nil)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/user", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		resp, _ := app.Test(req)

		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)
	})

	t.Run("when body cant parsing should return error", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		userHandler := NewHandler(nil)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(fiber.MethodPost, "/user", strings.NewReader(`"invalid":"body"`))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		resp, _ := app.Test(req)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("when validator cant validate payload struct should return error", func(t *testing.T) {
		t.Run("invalid email", func(t *testing.T) {
			TestUserModel := RegisterPayload{
				Name:     TestUserName,
				Email:    TestInvalidMail,
				Password: TestPassword,
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&TestUserModel)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/user", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			resp, _ := app.Test(req)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})

		t.Run("invalid password", func(t *testing.T) {
			TestUserModel := RegisterPayload{
				Name:     TestUserName,
				Email:    TestEmail,
				Password: TestInvalidPassword,
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&TestUserModel)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/user", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			resp, _ := app.Test(req)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})
	})

	t.Run("when user service return error should return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().Register(gomock.Any(), &TestUserModel).Return(
			nil,
			cerror.NewError(fiber.StatusInternalServerError, "something went wrong"),
		)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/user", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		resp, _ := app.Test(req)

		assert.Equal(t, resp.StatusCode, fiber.StatusInternalServerError)
	})
}

func TestHandler_UpdateUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		TestUpdateUserPayload := &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		}

		app := fiber.New()

		jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
			PrivateKey: TestPrivateKey,
			PublicKey:  TestPublicKey,
		})
		require.NoError(t, err)

		expirationTime := time.Now().UTC().Add(10 * time.Minute)
		accessToken, err := jwtGenerator.GenerateAccessToken(expirationTime, TestUserName, TestEmail, TestUserId)
		require.NoError(t, err)

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			VerifyAccessToken(gomock.Any(), accessToken).
			Return(&jwt_generator.Claims{
				Name:  TestUserName,
				Email: TestEmail,
				Role:  RoleUser,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    jwt_generator.IssuerDefault,
					Subject:   TestUserId,
					ExpiresAt: jwt.NewNumericDate(expirationTime),
					IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				},
			}, nil)
		mockUserService.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(&jwt_generator.Tokens{
				AccessToken:  TestAccessToken,
				RefreshToken: TestRefreshToken,
			}, nil)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		payload, err := json.Marshal(TestUpdateUserPayload)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(payload))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		bearerToken := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Set(fiber.HeaderAuthorization, bearerToken)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("Email", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Email: TestEmail,
			}

			app := fiber.New()

			jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
				PrivateKey: TestPrivateKey,
				PublicKey:  TestPublicKey,
			})
			require.NoError(t, err)

			expirationTime := time.Now().UTC().Add(10 * time.Minute)
			accessToken, err := jwtGenerator.GenerateAccessToken(expirationTime, TestUserName, TestEmail, TestUserId)
			require.NoError(t, err)

			mockUserService := NewMockService(mockController)
			mockUserService.
				EXPECT().
				VerifyAccessToken(gomock.Any(), accessToken).
				Return(&jwt_generator.Claims{
					Name:  TestUserName,
					Email: TestEmail,
					Role:  RoleUser,
					RegisteredClaims: jwt.RegisteredClaims{
						ID:        uuid.New().String(),
						Issuer:    jwt_generator.IssuerDefault,
						Subject:   TestUserId,
						ExpiresAt: jwt.NewNumericDate(expirationTime),
						IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
					},
				}, nil)
			mockUserService.
				EXPECT().
				UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
				Return(&jwt_generator.Tokens{
					AccessToken:  TestAccessToken,
					RefreshToken: TestRefreshToken,
				}, nil)

			userHandler := NewHandler(mockUserService)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			bearerToken := fmt.Sprintf("Bearer %s", accessToken)
			req.Header.Set(fiber.HeaderAuthorization, bearerToken)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		})

		t.Run("Name", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Name: TestUserName,
			}

			app := fiber.New()

			jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
				PrivateKey: TestPrivateKey,
				PublicKey:  TestPublicKey,
			})
			require.NoError(t, err)

			expirationTime := time.Now().UTC().Add(10 * time.Minute)
			accessToken, err := jwtGenerator.GenerateAccessToken(expirationTime, TestUserName, TestEmail, TestUserId)
			require.NoError(t, err)

			mockUserService := NewMockService(mockController)
			mockUserService.
				EXPECT().
				VerifyAccessToken(gomock.Any(), accessToken).
				Return(&jwt_generator.Claims{
					Name:  TestUserName,
					Email: TestEmail,
					Role:  RoleUser,
					RegisteredClaims: jwt.RegisteredClaims{
						ID:        uuid.New().String(),
						Issuer:    jwt_generator.IssuerDefault,
						Subject:   TestUserId,
						ExpiresAt: jwt.NewNumericDate(expirationTime),
						IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
					},
				}, nil)
			mockUserService.
				EXPECT().
				UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
				Return(&jwt_generator.Tokens{
					AccessToken:  TestAccessToken,
					RefreshToken: TestRefreshToken,
				}, nil)

			userHandler := NewHandler(mockUserService)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			bearerToken := fmt.Sprintf("Bearer %s", accessToken)
			req.Header.Set(fiber.HeaderAuthorization, bearerToken)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		})

		t.Run("Password", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Password: TestPassword,
			}

			app := fiber.New()

			jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
				PrivateKey: TestPrivateKey,
				PublicKey:  TestPublicKey,
			})
			require.NoError(t, err)

			expirationTime := time.Now().UTC().Add(10 * time.Minute)
			accessToken, err := jwtGenerator.GenerateAccessToken(expirationTime, TestUserName, TestEmail, TestUserId)
			require.NoError(t, err)

			mockUserService := NewMockService(mockController)
			mockUserService.
				EXPECT().
				VerifyAccessToken(gomock.Any(), accessToken).
				Return(&jwt_generator.Claims{
					Name:  TestUserName,
					Email: TestEmail,
					Role:  RoleUser,
					RegisteredClaims: jwt.RegisteredClaims{
						ID:        uuid.New().String(),
						Issuer:    jwt_generator.IssuerDefault,
						Subject:   TestUserId,
						ExpiresAt: jwt.NewNumericDate(expirationTime),
						IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
					},
				}, nil)
			mockUserService.
				EXPECT().
				UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
				Return(&jwt_generator.Tokens{
					AccessToken:  TestAccessToken,
					RefreshToken: TestRefreshToken,
				}, nil)

			userHandler := NewHandler(mockUserService)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			bearerToken := fmt.Sprintf("Bearer %s", accessToken)
			req.Header.Set(fiber.HeaderAuthorization, bearerToken)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		})

		t.Run("when all field is empty should return error", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Name:     "",
				Email:    "",
				Password: "",
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			jwtGenerator, err := jwt_generator.NewJwtGenerator(config.JwtConfig{
				PrivateKey: TestPrivateKey,
				PublicKey:  TestPublicKey,
			})
			require.NoError(t, err)

			expirationTime := time.Now().UTC().Add(10 * time.Minute)
			accessToken, err := jwtGenerator.GenerateAccessToken(expirationTime, TestUserName, TestEmail, TestUserId)
			require.NoError(t, err)

			mockUserService := NewMockService(mockController)
			mockUserService.
				EXPECT().
				VerifyAccessToken(gomock.Any(), accessToken).
				Return(&jwt_generator.Claims{
					Name:  TestUserName,
					Email: TestEmail,
					Role:  RoleUser,
					RegisteredClaims: jwt.RegisteredClaims{
						ID:        uuid.New().String(),
						Issuer:    jwt_generator.IssuerDefault,
						Subject:   TestUserId,
						ExpiresAt: jwt.NewNumericDate(expirationTime),
						IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
					},
				}, nil)

			userHandler := NewHandler(mockUserService)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			bearerToken := fmt.Sprintf("Bearer %s", accessToken)
			req.Header.Set(fiber.HeaderAuthorization, bearerToken)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})
	})
}

func TestHandler_Login(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		TestUserModel := LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		}
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().Login(gomock.Any(), &TestUserModel).Return(&jwt_generator.Tokens{
			AccessToken:  TestAccessToken,
			RefreshToken: TestRefreshToken,
		}, nil)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(
			fiber.MethodGet,
			fmt.Sprintf("/user/email/%s/password/%s", TestUserModel.Email, TestUserModel.Password),
			nil,
		)
		resp, _ := app.Test(req)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("when user service return error should return it", func(t *testing.T) {
		TestUserModel := LoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		}
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().Login(gomock.Any(), &TestUserModel).Return(
			nil,
			cerror.NewError(fiber.StatusInternalServerError, "something went wrong"),
		)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(
			fiber.MethodGet,
			fmt.Sprintf("/user/email/%s/password/%s", TestUserModel.Email, TestUserModel.Password),
			nil,
		)
		resp, _ := app.Test(req)

		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	})
}

func TestHandler_GetAccessTokenByRefreshToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			GetAccessTokenByRefreshToken(gomock.Any(), TestUserId, TestRefreshToken).
			Return(TestAccessToken, nil)

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		request := httptest.NewRequest(
			fiber.MethodGet,
			fmt.Sprintf("/user/%s/refreshToken/%s", TestUserId, TestRefreshToken),
			nil,
		)
		response, _ := app.Test(request)
		body, _ := io.ReadAll(response.Body)

		assert.Equal(t, fiber.StatusOK, response.StatusCode)
		assert.Equal(t,
			string(body),
			fmt.Sprintf(`{"accessToken":"%s"}`, TestAccessToken),
		)
	})

	t.Run("when user service return error should return it", func(t *testing.T) {
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			GetAccessTokenByRefreshToken(gomock.Any(), TestUserId, TestRefreshToken).
			Return("", cerror.NewError(fiber.StatusInternalServerError, "something went wrong"))

		userHandler := NewHandler(mockUserService)
		userHandler.RegisterRoutes(app)

		request := httptest.NewRequest(
			fiber.MethodGet,
			fmt.Sprintf("/user/%s/refreshToken/%s", TestUserId, TestRefreshToken),
			nil,
		)
		response, _ := app.Test(request)

		assert.Equal(t, fiber.StatusInternalServerError, response.StatusCode)
	})
}
