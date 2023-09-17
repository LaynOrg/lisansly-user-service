package logger

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestInjectContext(t *testing.T) {
	ctx := context.Background()

	logProd, err := zap.NewProduction()
	require.NoError(t, err)

	log := logProd.Sugar()
	defer log.Sync()

	ctx = InjectContext(ctx, log)

	logFromCtx := ctx.Value(ContextLoggerValue).(*zap.SugaredLogger)
	assert.NotNil(t, logFromCtx)
}

func TestFromContext(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		logProd, err := zap.NewProduction()
		require.NoError(t, err)

		log := logProd.Sugar()
		defer log.Sync()

		ctx := context.Background()
		ctx = InjectContext(ctx, log)

		logFromCtx, ok := FromContext(ctx)

		assert.True(t, ok)
		assert.NotNil(t, logFromCtx)
	})

	t.Run("when logger value is empty in ctx should return false", func(t *testing.T) {
		ctx := context.Background()
		logFromCtx, ok := FromContext(ctx)

		assert.False(t, ok)
		assert.Nil(t, logFromCtx)
	})
}
