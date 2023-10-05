package cerror

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestCustomError_SerializeCerror(t *testing.T) {
	cerr := &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "test error",
		LogSeverity:    zapcore.ErrorLevel,
		LogFields: []zap.Field{
			zap.String("key", "value"),
		},
	}
	serializedCerr := cerr.SerializeCerror()

	assert.Error(t, serializedCerr)
	assert.NotEmpty(t, serializedCerr)
}
