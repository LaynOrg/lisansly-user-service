package logger

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

const ContextKey = "logger"

func Middleware(logger Logger) func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		ctx.Locals(ContextKey, logger)
		return ctx.Next()
	}
}

func FromContext(ctx context.Context) Logger {
	var (
		logger Logger
		ok     bool
	)

	logger, ok = ctx.Value(ContextKey).(Logger)
	if !ok {
		logger = NewLogger()
		return logger
	}

	return logger
}

func InjectContext(ctx context.Context, log Logger) context.Context {
	return context.WithValue(ctx, ContextKey, log)
}
