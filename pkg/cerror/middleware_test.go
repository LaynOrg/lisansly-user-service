package cerror

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"user-api/pkg/logger"
)

func TestErrorHandler(t *testing.T) {
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
	cerr := ErrorHandler(log, testError)

	assert.Error(t, cerr)
	assert.Equal(t,
		errors.New("{\"httpStatus\":500}"),
		cerr,
	)
}
