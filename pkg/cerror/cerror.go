package cerror

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type CustomError interface {
	Error() string
	Code() int
	Fields() []zap.Field
	Severity() zapcore.Level
	SetSeverity(level zapcore.Level) CustomError
}

type customError struct {
	code     int
	message  string
	severity zapcore.Level
	fields   []zap.Field
}

func NewError(code int, message string, fields ...zap.Field) CustomError {
	return &customError{
		code:     code,
		message:  message,
		severity: zap.ErrorLevel,
		fields:   fields,
	}
}

func (e *customError) Error() string {
	return e.message
}

func (e *customError) Code() int {
	return e.code
}

func (e *customError) Fields() []zap.Field {
	return e.fields
}

func (e *customError) Severity() zapcore.Level {
	return e.severity
}

func (e *customError) SetSeverity(level zapcore.Level) CustomError {
	e.severity = level
	return e
}
