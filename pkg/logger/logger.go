package logger

import (
	"go.uber.org/zap"
)

type Logger interface {
	Desugar() *zap.Logger
	With(args ...interface{}) *zap.SugaredLogger
	WithOptions(opts ...zap.Option) *zap.SugaredLogger

	Error(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Fatal(args ...interface{})
}

type logger struct {
	*zap.SugaredLogger
}

func NewLogger() Logger {
	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer log.Sync() //nolint:errcheck

	return &logger{
		log.Sugar(),
	}
}
