package cerror

import (
	"context"
	"errors"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"user-api/pkg/logger"
)

type (
	lambdaHandler func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)
	errorHandler  func(ctx context.Context, err error) (events.APIGatewayProxyResponse, error)
)

func WithMiddleware(
	log *zap.SugaredLogger,
	errorHandler errorHandler,
	handler lambdaHandler,
) lambdaHandler {
	return func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		ctx = logger.InjectContext(ctx, log)
		response, err := handler(ctx, request)
		if err != nil {
			return errorHandler(ctx, err)
		}

		return response, nil
	}
}

func ErrorHandler(ctx context.Context, err error) (events.APIGatewayProxyResponse, error) {
	var cerr *CustomError
	isCerror := errors.As(err, &cerr)
	if !isCerror {
		return events.APIGatewayProxyResponse{}, err
	}

	sugaredLogger := logger.FromContext(ctx)
	log := sugaredLogger.Desugar()
	if len(cerr.LogFields) > 0 {
		for _, field := range cerr.LogFields {
			log = log.With(field)
		}
	}
	log.Log(cerr.LogSeverity, cerr.LogMessage)

	serializedCerr := cerr.SerializeCerror()
	return events.APIGatewayProxyResponse{}, serializedCerr
}
