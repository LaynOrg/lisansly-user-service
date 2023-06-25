package cerror

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type CustomError struct {
	error
	Code        int
	LogMessage  string
	LogSeverity zapcore.Level
	LogFields   []zap.Field
}
