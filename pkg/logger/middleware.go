package logger

import (
	"context"

	"go.uber.org/zap"
)

func InjectContext(ctx context.Context, logger *zap.SugaredLogger) context.Context {
	ctx = context.WithValue(ctx, ContextLoggerValue, logger)
	return ctx
}

func FromContext(ctx context.Context) (*zap.SugaredLogger, bool) {
	logger, ok := ctx.Value(ContextLoggerValue).(*zap.SugaredLogger)
	if !ok {
		return nil, false
	}

	return logger, true
}
