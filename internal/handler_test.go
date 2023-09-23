package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	assert.Implements(t, (*Handler)(nil), h)
}

func TestHandler_CreateUser(t *testing.T) {
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
		log, _ := zap.NewProduction()
		h := NewHandler(mockUserService, nil, log.Sugar(), validator.New())

		reqBody, err := json.Marshal(&RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(reqBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

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
		log, _ := zap.NewProduction()
		h := NewHandler(mockUserService, nil, log.Sugar(), validator.New())

		reqBody, err := json.Marshal(&RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(reqBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
		assert.NoError(t, cerr)
	})

	t.Run("when get ambiguous request body should return error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		log, _ := zap.NewProduction()
		h := NewHandler(nil, nil, log.Sugar(), validator.New())

		response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            `{"key":"value"`,
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("name", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			log, _ := zap.NewProduction()
			h := NewHandler(nil, nil, log.Sugar(), validator.New())

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     "",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			})
			require.NoError(t, err)

			response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(reqBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("email", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			log, _ := zap.NewProduction()
			h := NewHandler(nil, nil, log.Sugar(), validator.New())

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     "test",
				Email:    "",
				Password: "Asdfg12345_",
			})
			require.NoError(t, err)

			response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(reqBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("password", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			log, _ := zap.NewProduction()
			h := NewHandler(nil, nil, log.Sugar(), validator.New())

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     "test",
				Email:    "test@test.com",
				Password: "123",
			})
			require.NoError(t, err)

			response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(reqBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
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
				errors.New("test error"),
			)
		log, _ := zap.NewProduction()

		h := NewHandler(mockUserService, nil, log.Sugar(), validator.New())

		reqBody, err := json.Marshal(&RegisterPayload{
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.CreateUser(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(reqBody),
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			errors.New("test error"),
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

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
		assert.NoError(t, cerr)
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

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
		assert.NoError(t, cerr)
	})

	t.Run("when request body is ambiguous should return error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd.abcd.abcd.abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(nil, nil, log, validator.New())

		response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            `{"key":"value"`,
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("email", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd.abcd.abcd.abcd",
			})

			logProd, err := zap.NewProduction()
			require.NoError(t, err)

			log := logProd.Sugar()
			defer log.Sync()

			h := NewHandler(nil, nil, log, validator.New())

			requestBody, err := json.Marshal(&LoginPayload{
				Email:    "",
				Password: "Asdfg12345_",
			})
			require.NoError(t, err)

			response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("password", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd.abcd.abcd.abcd",
			})

			logProd, err := zap.NewProduction()
			require.NoError(t, err)

			log := logProd.Sugar()
			defer log.Sync()

			h := NewHandler(nil, nil, log, validator.New())

			requestBody, err := json.Marshal(&LoginPayload{
				Email:    "test@test.com",
				Password: "123",
			})
			require.NoError(t, err)

			response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
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
			Return(nil, errors.New("test error"))

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&LoginPayload{
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.Login(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		assert.Empty(t, response)
		assert.Error(t, cerr)
		assert.Equal(t, errors.New("test error"), cerr)
	})
}

func TestHandler_GetUserById(t *testing.T) {
	testUser := &Table{
		Id:        "abcd-abcd-abcd-abcd",
		Name:      "test",
		Email:     "test@test.com",
		Password:  "Asdfg12345_",
		Role:      RoleUser,
		CreatedAt: time.Now().UTC(),
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), "abcd-abcd-abcd-abcd").
			Return(testUser, nil)

		h := NewHandler(nil, mockRepository, log, validator.New())

		requestBody, err := json.Marshal(&GetUserByIdPayload{
			UserId: "abcd-abcd-abcd-abcd",
		})
		require.NoError(t, err)

		response, err := h.GetUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var user *Table
		err = json.Unmarshal([]byte(response.Body), &user)
		require.NoError(t, err)

		assert.Equal(t, testUser, user)
		assert.NoError(t, err)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()
		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), "abcd-abcd-abcd-abcd").
			Return(testUser, nil)

		h := NewHandler(nil, mockRepository, log, validator.New())

		requestBody, err := json.Marshal(&GetUserByIdPayload{
			UserId: "abcd-abcd-abcd-abcd",
		})
		require.NoError(t, err)

		response, err := h.GetUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var user *Table
		err = json.Unmarshal([]byte(response.Body), &user)
		require.NoError(t, err)

		assert.Equal(t, testUser, user)
		assert.NoError(t, err)
	})

	t.Run("when request body is ambiguous should return error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(nil, nil, log, validator.New())

		response, cerr := h.GetUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            `{"key":"value"`,
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("validation error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(nil, nil, log, validator.New())

		requestBody, err := json.Marshal(&GetUserByIdPayload{
			UserId: "",
		})
		require.NoError(t, err)

		response, cerr := h.GetUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		mockRepository := NewMockRepository(mockController)
		mockRepository.
			EXPECT().
			FindUserWithId(gomock.Any(), "abcd-abcd-abcd-abcd").
			Return(nil, errors.New("test error"))

		h := NewHandler(nil, mockRepository, log, validator.New())

		requestBody, err := json.Marshal(&GetUserByIdPayload{
			UserId: "abcd-abcd-abcd-abcd",
		})
		require.NoError(t, err)

		response, cerr := h.GetUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t, errors.New("test error"), cerr)
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

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					UserId:   userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&UpdateUserPayload{
			UserId:   userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					UserId:   userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(&jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}, nil)

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&UpdateUserPayload{
			UserId:   userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal([]byte(response.Body), &tokens)
		require.NoError(t, err)

		assert.NoError(t, cerr)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  "abcd.abcd.abcd",
			RefreshToken: "abcd.abcd.abcd",
		}, tokens)
	})

	t.Run("when request body is ambiguous should return error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		h := NewHandler(nil, nil, log, validator.New())

		response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			Body:            `{"key":"value"`,
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("user id", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			logProd, err := zap.NewProduction()
			require.NoError(t, err)

			log := logProd.Sugar()
			defer log.Sync()

			h := NewHandler(nil, nil, log, validator.New())

			requestBody, err := json.Marshal(&UpdateUserPayload{
				UserId:   "abcdabcd",
				Name:     "test",
				Email:    "test@test.com",
				Password: "Asdfg12345_",
			})
			require.NoError(t, err)

			response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Accept":       "application/json",
					"Content-Type": "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("other fields is empty ", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			logProd, err := zap.NewProduction()
			require.NoError(t, err)

			log := logProd.Sugar()
			defer log.Sync()

			h := NewHandler(nil, nil, log, validator.New())

			requestBody, err := json.Marshal(&UpdateUserPayload{
				UserId:   uuid.NewString(),
				Name:     "",
				Email:    "",
				Password: "",
			})
			require.NoError(t, err)

			response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Accept":       "application/json",
					"Content-Type": "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		userId := uuid.NewString()
		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			UpdateUserById(
				gomock.Any(),
				userId,
				&UpdateUserPayload{
					UserId:   userId,
					Name:     "test",
					Email:    "test@test.com",
					Password: "Asdfg12345_",
				},
			).
			Return(nil, errors.New("test error"))

		h := NewHandler(mockService, nil, log, validator.New())

		requestBody, err := json.Marshal(&UpdateUserPayload{
			UserId:   userId,
			Name:     "test",
			Email:    "test@test.com",
			Password: "Asdfg12345_",
		})
		require.NoError(t, err)

		response, cerr := h.UpdateUserById(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t, errors.New("test error"), cerr)
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

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				"abcd-abcd-abcd-abcd",
				"abcd.abcd.abcd",
			).
			Return(
				&AccessTokenPayload{
					Token: "abcd.abcd.abcd",
				},
				nil,
			)

		logger, _ := zap.NewProduction()
		defer logger.Sync()

		h := NewHandler(mockService, nil, logger.Sugar(), validator.New())

		requestBody, err := json.Marshal(&GetAccessTokenViaRefreshTokenPayload{
			UserId:       "abcd-abcd-abcd-abcd",
			RefreshToken: "abcd.abcd.abcd",
		})
		require.NoError(t, err)

		response, err := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var responseBody map[string]any
		err = json.Unmarshal([]byte(response.Body), &responseBody)

		assert.Equal(t, "abcd.abcd.abcd", responseBody["accessToken"])
		assert.NoError(t, err)
	})

	t.Run("when lambda context is empty", func(t *testing.T) {
		ctx := context.Background()

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				"abcd-abcd-abcd-abcd",
				"abcd.abcd.abcd",
			).
			Return(
				&AccessTokenPayload{
					Token: "abcd.abcd.abcd",
				},
				nil,
			)

		logger, _ := zap.NewProduction()
		defer logger.Sync()

		h := NewHandler(mockService, nil, logger.Sugar(), validator.New())

		requestBody, err := json.Marshal(&GetAccessTokenViaRefreshTokenPayload{
			UserId:       "abcd-abcd-abcd-abcd",
			RefreshToken: "abcd.abcd.abcd",
		})
		require.NoError(t, err)

		response, err := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		var responseBody map[string]any
		err = json.Unmarshal([]byte(response.Body), &responseBody)

		assert.Equal(t, "abcd.abcd.abcd", responseBody["accessToken"])
		assert.NoError(t, err)
	})

	t.Run("when request body is ambiguous should return error", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		logger, _ := zap.NewProduction()
		defer logger.Sync()

		h := NewHandler(nil, nil, logger.Sugar(), validator.New())

		response, cerr := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            `{"key":"value"`,
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			cerror.ErrorBadRequest.HttpStatusCode,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, response)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Run("user id", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			logger, _ := zap.NewProduction()
			defer logger.Sync()

			h := NewHandler(nil, nil, logger.Sugar(), validator.New())

			requestBody, err := json.Marshal(&GetAccessTokenViaRefreshTokenPayload{
				UserId:       "",
				RefreshToken: "abcd.abcd.abcd",
			})
			require.NoError(t, err)

			response, cerr := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})

		t.Run("refresh token", func(t *testing.T) {
			ctx := context.Background()
			ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
				AwsRequestID: "abcd-abcd-abcd-abcd",
			})

			logger, _ := zap.NewProduction()
			defer logger.Sync()

			h := NewHandler(nil, nil, logger.Sugar(), validator.New())

			requestBody, err := json.Marshal(&GetAccessTokenViaRefreshTokenPayload{
				UserId:       "",
				RefreshToken: "abcd.abcdabcd",
			})
			require.NoError(t, err)

			response, cerr := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:            string(requestBody),
				IsBase64Encoded: false,
			})

			assert.Error(t, cerr)
			assert.Equal(t,
				cerror.ErrorBadRequest.HttpStatusCode,
				cerr.(*cerror.CustomError).HttpStatusCode,
			)
			assert.Empty(t, response)
		})
	})

	t.Run("when service return error should return it", func(t *testing.T) {
		ctx := context.Background()
		ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
			AwsRequestID: "abcd-abcd-abcd-abcd",
		})

		mockService := NewMockService(mockController)
		mockService.
			EXPECT().
			GetAccessTokenByRefreshToken(
				gomock.Any(),
				"abcd-abcd-abcd-abcd",
				"abcd.abcd.abcd",
			).
			Return(
				nil,
				errors.New("test error"),
			)

		logger, _ := zap.NewProduction()
		defer logger.Sync()

		h := NewHandler(mockService, nil, logger.Sugar(), validator.New())

		requestBody, err := json.Marshal(&GetAccessTokenViaRefreshTokenPayload{
			UserId:       "abcd-abcd-abcd-abcd",
			RefreshToken: "abcd.abcd.abcd",
		})
		require.NoError(t, err)

		response, cerr := h.GetAccessTokenViaRefreshToken(ctx, events.APIGatewayProxyRequest{
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			Body:            string(requestBody),
			IsBase64Encoded: false,
		})

		assert.Error(t, cerr)
		assert.Equal(t, errors.New("test error"), cerr)
		assert.Empty(t, response)
	})
}
