//go:build unit

package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	log := NewLogger()

	assert.Implements(t, (*Logger)(nil), log)
}
