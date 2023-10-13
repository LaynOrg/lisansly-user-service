package cerror

import (
	"errors"

	"github.com/goccy/go-json"
	"go.uber.org/zap/zapcore"
)

type CustomError struct {
	error          `json:"-"`
	HttpStatusCode int             `json:"httpStatus"`
	LogMessage     string          `json:"-"`
	LogSeverity    zapcore.Level   `json:"-"`
	LogFields      []zapcore.Field `json:"-"`
}

func (cerr *CustomError) SerializeCerror() error {
	var marshalledToByte []byte
	marshalledToByte, _ = json.Marshal(&cerr)

	return errors.New(string(marshalledToByte))
}
