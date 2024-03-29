package user

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"user-service/pkg/cerror"
	"user-service/pkg/jwt_generator"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil)
	assert.Implements(t, (*Handler)(nil), h)
}

func TestHandler_Register(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			Register(gomock.Any(), &RegisterPayload{
				Name:     "test",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(
				&jwt_generator.Tokens{
					AccessToken:  "abcd.abcd.abcd",
					RefreshToken: "abcd.abcd.abcd",
				},
				nil,
			)

		h := NewHandler(mockUserService, nil)
		tokens, cerr := h.Register(ctx, &RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
		assert.NoError(t, cerr)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			Register(gomock.Any(), &RegisterPayload{
				Name:     "test",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(
				&jwt_generator.Tokens{
					AccessToken:  "abcd.abcd.abcd",
					RefreshToken: "abcd.abcd.abcd",
				},
				nil,
			)

		h := NewHandler(mockUserService, nil)
		tokens, cerr := h.Register(ctx, &RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
		assert.NoError(t, cerr)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("name", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.Register(ctx, &RegisterPayload{
				Name:     "",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			})

			var unmarshalledCerr *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerr)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerr.HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("email", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.Register(ctx, &RegisterPayload{
				Name:     "test",
				Email:    "",
				Password: "Asdfg12345_",
			})

			var unmarshalledCerr *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerr)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerr.HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("password", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.Register(ctx, &RegisterPayload{
				Name:     "test",
				Email:    "test@test.com",
				Password: "123",
			})

			var unmarshalledCerr *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerr)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerr.HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			Register(gomock.Any(), &RegisterPayload{
				Name:     "test",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		h := NewHandler(mockUserService, nil)
		response, cerr := h.Register(ctx, &RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New(`{"httpStatus":500}`),
			cerr,
		)
		assert.Empty(t, response)
	})
}

func TestHandler_Login(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd.abcd.abcd.abcd",
		})

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			Login(gomock.Any(), &LoginPayload{
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil)
		tokens, cerr := h.Login(ctx, &LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			Login(gomock.Any(), &LoginPayload{
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil)
		tokens, cerr := h.Login(ctx, &LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("email", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd.abcd.abcd.abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.Login(ctx, &LoginPayload{
				Email:    "",
				Password: "Asdfg12345_",
			})
			assert.Error(t, cerr)

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("password", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd.abcd.abcd.abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.Login(ctx, &LoginPayload{
				Email:    "test@test.com",
				Password: "123",
			})
			assert.Error(t, cerr)

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd.abcd.abcd.abcd",
		})

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			Login(gomock.Any(), &LoginPayload{
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			}).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		h := NewHandler(mockService, nil)
		response, cerr := h.Login(ctx, &LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.Empty(t, response)
		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New(`{"httpStatus":500}`),
			cerr,
		)
	})
}

func TestHandler_GetUserById(t *testing.T) {
	testUser := &Table{
		ID:        "abcd-abcd-abcd-abcd",
		Name:      "test",
		Email:     "test@test.com",
		Password:  "Asdfg12345_",
		Plan:      PlanDefault,
		CreatedAt: time.Now().UTC(),
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		userId := uuid.NewString()
		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), userId).
			Return(testUser, nil)

		h := NewHandler(nil, mockRepository)
		user, err := h.GetUserById(ctx, &GetUserByIdPayload{
			ID: userId,
		})

		assert.Equal(t, testUser, user)
		assert.NoError(t, err)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		userId := uuid.NewString()

		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), userId).
			Return(testUser, nil)

		h := NewHandler(nil, mockRepository)
		user, err := h.GetUserById(ctx, &GetUserByIdPayload{
			ID: userId,
		})

		assert.Equal(t, testUser, user)
		assert.NoError(t, err)
	})

	t.Run("validation error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		h := NewHandler(nil, nil)
		response, cerr := h.GetUserById(ctx, &GetUserByIdPayload{
			ID: "",
		})
		assert.Error(t, cerr)

		var unmarshalledCerror *cerror.CustomError
		err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
		require.NoError(t, err)

		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			unmarshalledCerror.HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})
		userId := uuid.NewString()

		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), userId).
			Return(
				nil, &cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		h := NewHandler(nil, mockRepository)
		response, cerr := h.GetUserById(ctx, &GetUserByIdPayload{
			ID: userId,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New(`{"httpStatus":500}`),
			cerr,
		)
		assert.Empty(t, response)
	})
}

func TestHandler_UpdateUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					ID:       userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil)
		tokens, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
			ID:       userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					ID:       userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil)
		tokens, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
			ID:       userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("user id", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
				ID:       "abcdabcd",
				Name:     "test",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			})
			assert.Error(t, cerr)

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("at least one of user fields is full except for the userId", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			userId := uuid.NewString()
			mockService := NewMockService(mockController)
			mockService.
				EXPECT().
				UpdateUserById(
					gomock.Any(),
					userId,
					gomock.Any(),
				).
				Return(&jwt_generator.Tokens{
					AccessToken:  "abcd.abcd.abcd",
					RefreshToken: "abcd.abcd.abcd",
				}, nil)

			h := NewHandler(mockService, nil)
			response, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
				ID:       userId,
				Name:     "test",
				Email:    "",
				Password: "",
			})

			assert.NoError(t, cerr)
			assert.NotEmpty(t, response)
		})

		t.Run("other fields is empty ", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
				ID:       uuid.NewString(),
				Name:     "",
				Email:    "",
				Password: "",
			})

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					ID:       userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		h := NewHandler(mockService, nil)

		response, cerr := h.UpdateUserById(ctx, &UpdateUserPayload{
			ID:       userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New(`{"httpStatus":500}`),
			cerr,
		)
		assert.Empty(t, response)
	})
}

func TestHandler_GetAccessTokenViaRefreshToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})
		userId := uuid.NewString()

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				userId,
				"abcd.abcd.abcd",
			).
			Return(
				&AccessTokenPayload{
					Token: "abcd.abcd.abcd",
				},
				nil,
			)

		h := NewHandler(mockService, nil)
		response, err := h.GetAccessTokenViaRefreshToken(ctx, &GetAccessTokenViaRefreshTokenPayload{
			UserID:       userId,
			RefreshToken: "abcd.abcd.abcd",
		})

		assert.NoError(t, err)
		assert.Equal(t, "abcd.abcd.abcd", response.Token)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		userId := uuid.NewString()

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				userId,
				"abcd.abcd.abcd",
			).
			Return(
				&AccessTokenPayload{
					Token: "abcd.abcd.abcd",
				},
				nil,
			)

		h := NewHandler(mockService, nil)
		response, err := h.GetAccessTokenViaRefreshToken(ctx, &GetAccessTokenViaRefreshTokenPayload{
			UserID:       userId,
			RefreshToken: "abcd.abcd.abcd",
		})

		assert.NoError(t, err)
		assert.Equal(t, "abcd.abcd.abcd", response.Token)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("user id", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			h := NewHandler(nil, nil)
			response, cerr := h.GetAccessTokenViaRefreshToken(ctx, &GetAccessTokenViaRefreshTokenPayload{
				UserID:       "notValid",
				RefreshToken: "abcd.abcd.abcd",
			})

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("refresh token", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})
			userId := uuid.NewString()

			h := NewHandler(nil, nil)
			response, cerr := h.GetAccessTokenViaRefreshToken(ctx, &GetAccessTokenViaRefreshTokenPayload{
				UserID:       userId,
				RefreshToken: "",
			})

			var unmarshalledCerror *cerror.CustomError
			err := json.Unmarshal([]byte(cerr.Error()), &unmarshalledCerror)
			require.NoError(t, err)

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				unmarshalledCerror.HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})
		userId := uuid.NewString()

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				userId,
				"abcd.abcd.abcd",
			).
			Return(
				nil,
				&cerror.CustomError{
					HttpStatusCode: http.StatusInternalServerError,
				},
			)

		h := NewHandler(mockService, nil)
		response, cerr := h.GetAccessTokenViaRefreshToken(ctx, &GetAccessTokenViaRefreshTokenPayload{
			UserID:       userId,
			RefreshToken: "abcd.abcd.abcd",
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New(`{"httpStatus":500}`),
			cerr,
		)
		assert.Empty(t, response)
	})
}
