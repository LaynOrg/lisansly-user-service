//go:build unit

package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
	"user-api/pkg/server"
)

const (
	TestInvalidMail  = "invalid-mail.com"
	TestRefreshToken = "abcd.abcd.abcd"
	TestAccessToken  = "abcd.abcd.abcd"
)

func TestNewHandler(t *testing.T) {
	userHandler := NewHandler(nil)

	assert.Implements(t, (*server.Handler)(nil), userHandler)
}

func TestHandler_Register(t *testing.T) {
	TestUserModel := UserPayload{
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
		TestUserModel := UserPayload{
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

func TestHandler_Login(t *testing.T) {
	TestUserModel := UserPayload{
		Email:    TestEmail,
		Password: TestPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
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

func TestHandler_Token(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			GetAccessToken(gomock.Any(), TestUserId, TestRefreshToken).
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
			GetAccessToken(gomock.Any(), TestUserId, TestRefreshToken).
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
