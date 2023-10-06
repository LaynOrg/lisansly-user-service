package cerror

import "go.uber.org/zap"

func ErrorHandler(sugaredLogger *zap.SugaredLogger, cerr *CustomError) error {
	log := sugaredLogger.Desugar()
	if len(cerr.LogFields) > 0 {
		for _, field := range cerr.LogFields {
			log = log.With(field)
		}
	}
	log.Log(cerr.LogSeverity, cerr.LogMessage)

	serializedCerr := cerr.SerializeCerror()
	return serializedCerr
}
