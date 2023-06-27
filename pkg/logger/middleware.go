package logger

import (
	"context"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

const (
	ContextKey                = "logger"
	EventFinishedSuccessfully = "event successfully finished"
)

func Middleware(logger *zap.SugaredLogger) func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		ctx.Locals(ContextKey, logger)
		return ctx.Next()
	}
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	var (
		logger *zap.SugaredLogger
		isOk   bool
	)

	logger, isOk = ctx.Value(ContextKey).(*zap.SugaredLogger)
	if !isOk {
		l, _ := zap.NewProduction()
		logger = l.Sugar()
	}

	var lambdaCtx *lambdacontext.LambdaContext
	lambdaCtx, isOk = lambdacontext.FromContext(ctx)
	if isOk {
		logger.With(zap.String("requestId", lambdaCtx.AwsRequestID))
	}

	return logger
}

func InjectContext(ctx context.Context, log *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, ContextKey, log)
}
