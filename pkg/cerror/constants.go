package cerror

import (
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

	ErrorBuildExpression = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while build update expression",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorUserNotFound = &CustomError{
		HttpStatusCode: http.StatusNotFound,
		LogMessage:     "user not found",
		LogSeverity:    zapcore.ErrorLevel,
	}
)
