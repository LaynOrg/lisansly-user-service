package logger

import (
	"context"

	"go.uber.org/zap"
)

func InjectContext(ctx context.Context, logger *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, ContextLoggerValue, logger)
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	logger, ok := ctx.Value(ContextLoggerValue).(*zap.SugaredLogger)
	if !ok {
		log, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}
		_ = log.Sync()

		return log.Sugar()
	}

	return logger
}
