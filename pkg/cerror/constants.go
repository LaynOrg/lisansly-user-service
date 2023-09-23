package cerror

import (
	"go.uber.org/zap"
	"net/http"

	"go.uber.org/zap/zapcore"
)

var (
	ErrorBadRequest = &CustomError{
		HttpStatusCode: http.StatusBadRequest,
		LogMessage:     "malformed request body or query parameter",
		LogSeverity:    zapcore.WarnLevel,
	}

	ErrorGenerateAccessToken = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while generate access token",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorGenerateRefreshToken = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while generate access token",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorJsonMarshalling = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while marshalling response body",
		LogSeverity:    zap.ErrorLevel,
	}

	ErrorBuildExpression = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while build update expression",
		LogSeverity:    zap.ErrorLevel,
	}

	ErrorUserNotFound = &CustomError{
		HttpStatusCode: http.StatusNotFound,
		LogMessage:     "user not found",
		LogSeverity:    zap.ErrorLevel,
	}
)
