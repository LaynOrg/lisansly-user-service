//go:build unit

package logger

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMiddleware(t *testing.T) {
	l, _ := zap.NewProduction()
	log := l.Sugar()

	app := fiber.New()
	app.Use(Middleware(log)).Get("/", func(c *fiber.Ctx) error {
		assert.Equal(t, log, c.Context().Value(ContextKey))

		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestFromContext(t *testing.T) {
	t.Run("when context have logger instance should get from context and return logger instance", func(t *testing.T) {
		var log *zap.SugaredLogger

		app := fiber.New()
		app.Use(func(ctx *fiber.Ctx) error {
			logger, _ := zap.NewProduction()
			ctx.Locals(ContextKey, logger)
			return ctx.Next()
		})
		app.Post("/", func(ctx *fiber.Ctx) error {
			log = FromContext(ctx.Context())
			return nil
		})

		req := httptest.NewRequest(fiber.MethodPost, "/", nil)
		_, err := app.Test(req)
		require.NoError(t, err)

		assert.NotEmpty(t, log)
	})

	t.Run("when cant find logger in context should create new logger instance", func(t *testing.T) {
		ctx := context.Background()
		log := FromContext(ctx)

		assert.NotEmpty(t, log)
	})
}

func TestInjectContext(t *testing.T) {
	ctx := context.Background()
	l, _ := zap.NewProduction()
	log := l.Sugar()

	ctx = InjectContext(ctx, log)

	assert.Equal(t, log, ctx.Value(ContextKey))
}
