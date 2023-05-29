package cerror

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"

	"user-api/pkg/logger"
)

const StackSkipAmount = 7

func Middleware(ctx *fiber.Ctx, err error) error {
	var cerr *customError
	ok := errors.As(err, &cerr)
	if !ok {
		fiberError := err.(*fiber.Error)
		return ctx.SendStatus(fiberError.Code)
	}

	log := logger.FromContext(ctx.Context()).Desugar()
	if len(cerr.Fields()) > 0 {
		for _, field := range cerr.Fields() {
			log = log.With(field)
		}
	}
	log.WithOptions(
		zap.WithCaller(false),
		zap.AddCallerSkip(StackSkipAmount),
	).Log(cerr.Severity(), cerr.Error())

	return ctx.SendStatus(cerr.Code())
}
