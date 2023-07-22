//go:build unit

package user

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

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
	userHandler := NewHandler(nil, nil)

	assert.Implements(t, (*Handler)(nil), userHandler)
}

func TestHandler_CreateUser(t *testing.T) {
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

		userHandler := NewHandler(mockUserService, nil)
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

		userHandler := NewHandler(nil, nil)
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

			userHandler := NewHandler(nil, nil)
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

			userHandler := NewHandler(nil, nil)
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
			&cerror.CustomError{
				HttpStatusCode: fiber.StatusInternalServerError,
				LogMessage:     "something went wrong",
				LogSeverity:    zapcore.ErrorLevel,
			},
		)

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/user", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		resp, _ := app.Test(req)

		assert.Equal(t, resp.StatusCode, fiber.StatusInternalServerError)
	})
}

func TestHandler_GetUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

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

		userHandler := NewHandler(nil, mockUserRepository)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(fiber.MethodGet, fmt.Sprintf("/user/%s", TestUserId), nil)
		resp, _ := app.Test(req)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestHandler_UpdateUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	requestUrl := fmt.Sprintf("/user/%s", TestUserId)

	t.Run("happy path", func(t *testing.T) {
		TestUpdateUserPayload := &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestEmail,
			Password: TestPassword,
		}

		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			UpdateUserById(gomock.Any(), TestUserId, TestUpdateUserPayload).
			Return(&jwt_generator.Tokens{
				AccessToken:  TestAccessToken,
				RefreshToken: TestRefreshToken,
			}, nil)

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		payload, err := json.Marshal(TestUpdateUserPayload)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPatch, requestUrl, bytes.NewReader(payload))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("request body parsing error", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		userHandler := NewHandler(nil, nil)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(fiber.MethodPatch, requestUrl, strings.NewReader("invalid-json"))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("invalid email", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Email: "invalid-email",
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, requestUrl, bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})

		t.Run("invalid password", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Password: "123",
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, requestUrl, bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})

		t.Run("empty fields", func(t *testing.T) {
			TestUpdateUserPayload := &UpdateUserPayload{
				Name:     "",
				Email:    "",
				Password: "",
			}

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			payload, err := json.Marshal(TestUpdateUserPayload)
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, requestUrl, bytes.NewReader(payload))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

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

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(
			fiber.MethodPost,
			"/login",
			bytes.NewReader(reqBody),
		)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("invalid email", func(t *testing.T) {
			TestUserModel := LoginPayload{
				Email:    "invalid-email",
				Password: TestPassword,
			}
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			mockUserService := NewMockService(mockController)
			mockUserService.EXPECT().Login(gomock.Any(), &TestUserModel).Return(&jwt_generator.Tokens{
				AccessToken:  TestAccessToken,
				RefreshToken: TestRefreshToken,
			}, nil)

			reqBody, err := json.Marshal(TestUserModel)
			require.NoError(t, err)

			userHandler := NewHandler(mockUserService, nil)
			userHandler.RegisterRoutes(app)

			req := httptest.NewRequest(
				fiber.MethodPost,
				"/login",
				bytes.NewReader(reqBody),
			)
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})

		t.Run("invalid password", func(t *testing.T) {
			TestUserModel := LoginPayload{
				Email:    TestEmail,
				Password: "123",
			}
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			mockUserService := NewMockService(mockController)
			mockUserService.EXPECT().Login(gomock.Any(), &TestUserModel).Return(&jwt_generator.Tokens{
				AccessToken:  TestAccessToken,
				RefreshToken: TestRefreshToken,
			}, nil)

			userHandler := NewHandler(mockUserService, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&TestUserModel)
			require.NoError(t, err)

			req := httptest.NewRequest(
				fiber.MethodPost,
				"/login",
				bytes.NewReader(reqBody),
			)
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		})
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
			&cerror.CustomError{
				HttpStatusCode: fiber.StatusInternalServerError,
				LogMessage:     "something went wrong",
				LogSeverity:    zapcore.ErrorLevel,
			},
		)

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(
			fiber.MethodPost,
			"/login",
			bytes.NewReader(reqBody),
		)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
		resp, err := app.Test(req)
		require.NoError(t, err)

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

		userHandler := NewHandler(mockUserService, nil)
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
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			GetAccessTokenByRefreshToken(gomock.Any(), TestUserId, TestRefreshToken).
			Return(
				"",
				&cerror.CustomError{
					HttpStatusCode: fiber.StatusInternalServerError,
					LogMessage:     "something went wrong",
					LogSeverity:    zapcore.ErrorLevel,
				},
			)

		userHandler := NewHandler(mockUserService, nil)
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
