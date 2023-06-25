//go:build unit

package cerror

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMiddleware(t *testing.T) {
	t.Run("when custom error type error pass to middleware should resolve and return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: Middleware,
		})
		app.Get("/", func(ctx *fiber.Ctx) error {
			return &CustomError{
				Code:        fiber.StatusInternalServerError,
				LogMessage:  "something went wrong",
				LogSeverity: zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.String("key", "value"),
				},
			}
		})

		req, err := http.NewRequest(fiber.MethodGet, "/", nil)
		require.NoError(t, err)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("when error pass to middleware should resolve and return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: Middleware,
		})
		app.Get("/", func(ctx *fiber.Ctx) error {
			return fiber.NewError(fiber.StatusInternalServerError, "something went wrong")
		})

		req, err := http.NewRequest(fiber.MethodGet, "/", nil)
		require.NoError(t, err)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	})
}
