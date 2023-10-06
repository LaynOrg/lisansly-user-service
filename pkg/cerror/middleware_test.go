package cerror

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"user-api/pkg/logger"
)

var testErr error = &CustomError{
	HttpStatusCode: http.StatusInternalServerError,
	LogMessage:     "test error",
	LogSeverity:    zap.ErrorLevel,
	LogFields: []zap.Field{
		zap.Error(errors.New("test error")),
	},
}

func TestWithMiddleware(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		logProd, err := zap.NewProduction()
		require.NoError(t, err)
		log := logProd.Sugar()
		defer log.Sync()

		out := WithMiddleware(
			log,
			ErrorHandler,
			func(
				ctx context.Context,
				request events.APIGatewayProxyRequest,
			) (events.APIGatewayProxyResponse, error) {
				return events.APIGatewayProxyResponse{}, testErr
			},
		)

		ctx := context.Background()
		response, err := out(ctx, events.APIGatewayProxyRequest{})

		assert.Empty(t, response)
		assert.Equal(t, errors.New("{\"httpStatus\":500}"), err)
	})

	t.Run("when error is nil should skip request", func(t *testing.T) {
		logProd, err := zap.NewProduction()
		require.NoError(t, err)
		log := logProd.Sugar()
		defer log.Sync()

		out := WithMiddleware(
			log,
			ErrorHandler,
			func(
				ctx context.Context,
				request events.APIGatewayProxyRequest,
			) (events.APIGatewayProxyResponse, error) {
				return events.APIGatewayProxyResponse{
					StatusCode: http.StatusOK,
				}, nil
			})

		ctx := context.Background()
		response, err := out(ctx, events.APIGatewayProxyRequest{})

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.NoError(t, err)
	})
}

func TestErrorHandler(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		logProd, err := zap.NewProduction()
		require.NoError(t, err)
		log := logProd.Sugar()
		defer log.Sync()

		ctx = context.WithValue(ctx, logger.ContextLoggerValue, log)
		testError := &CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "test error",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(errors.New("test error")),
			},
		}
		response, err := ErrorHandler(ctx, testError)

		assert.Empty(t, response)
		assert.Equal(t, errors.New("{\"httpStatus\":500}"), err)
	})

	t.Run("when error is not type of cerror should return error", func(t *testing.T) {
		ctx := context.Background()
		logProd, err := zap.NewProduction()
		require.NoError(t, err)
		log := logProd.Sugar()
		defer log.Sync()

		ctx = context.WithValue(ctx, logger.ContextLoggerValue, log)
		response, err := ErrorHandler(ctx, errors.New("test error"))

		assert.Empty(t, response)
		assert.Error(t, err)
	})
}
