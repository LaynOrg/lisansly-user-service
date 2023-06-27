package cerror

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap/zapcore"
)

var (
	ErrorBadRequest = &CustomError{
		HttpStatusCode: fiber.StatusBadRequest,
		LogMessage:     "malformed request body or query parameter",
		LogSeverity:    zapcore.WarnLevel,
	}

	ErrorNotFound = &CustomError{
		HttpStatusCode: fiber.StatusNotFound,
		LogMessage:     "user not found",
		LogSeverity:    zapcore.WarnLevel,
	}

	ErrorGenerateAccessToken = &CustomError{
		HttpStatusCode: fiber.StatusInternalServerError,
		LogMessage:     "error occurred while generate access token",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorGenerateRefreshToken = &CustomError{
		HttpStatusCode: fiber.StatusInternalServerError,
		LogMessage:     "error occurred while generate access token",
		LogSeverity:    zapcore.ErrorLevel,
	}
)
