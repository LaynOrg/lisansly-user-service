//go:build unit

package logger

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	log := NewLogger()
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
		var log Logger

		app := fiber.New()
		app.Use(func(ctx *fiber.Ctx) error {
			logger := NewLogger()
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

		assert.Implements(t, (*Logger)(nil), log)
	})

	t.Run("when cant find logger in context should create new logger instance", func(t *testing.T) {
		ctx := context.Background()
		log := FromContext(ctx)

		assert.Implements(t, (*Logger)(nil), log)
	})
}

func TestInjectContext(t *testing.T) {
	ctx := context.Background()
	log := NewLogger()
	ctx = InjectContext(ctx, log)

	assert.Equal(t, log, ctx.Value(ContextKey))
}
