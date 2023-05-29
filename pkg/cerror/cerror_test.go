//go:build unit

package cerror

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewError(t *testing.T) {
	cerr := NewError(
		fiber.StatusInternalServerError,
		"error message",
		zap.String("key", "value"),
	)
	assert.Implements(t, (*CustomError)(nil), cerr)
}

func TestCustomError_Error(t *testing.T) {
	cerr := &customError{
		message: "error",
	}

	assert.Equal(t, "error", cerr.Error())
}

func TestCustomError_Code(t *testing.T) {
	cerr := &customError{
		code: fiber.StatusInternalServerError,
	}

	assert.Equal(t, fiber.StatusInternalServerError, cerr.Code())
}

func TestCustomError_Fields(t *testing.T) {
	var fields []zap.Field
	fields = append(fields, zap.String("key", "value"))

	cerr := &customError{
		fields: fields,
	}

	assert.Equal(t, fields, cerr.Fields())
}

func TestCustomError_Severity(t *testing.T) {
	cerr := &customError{
		severity: zapcore.WarnLevel,
	}

	assert.Equal(t, zapcore.WarnLevel, cerr.Severity())
}

func TestCustomError_SetSeverity(t *testing.T) {
	cerr := &customError{
		severity: zapcore.ErrorLevel,
	}

	_ = cerr.SetSeverity(zapcore.WarnLevel)

	assert.Equal(t, zapcore.WarnLevel, cerr.severity)
}
