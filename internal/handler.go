package user

import (
	"context"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-json"
	"go.uber.org/zap"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
	"user-api/pkg/logger"
)

type Handler interface {
	CreateUser(
		ctx context.Context,
		request events.APIGatewayProxyRequest,
	) (
		events.APIGatewayProxyResponse,
		error,
	)
	Login(
		ctx context.Context,
		request events.APIGatewayProxyRequest,
	) (
		events.APIGatewayProxyResponse,
		error,
	)
	GetUserById(
		ctx context.Context,
		request events.APIGatewayProxyRequest,
	) (
		events.APIGatewayProxyResponse,
		error,
	)
	UpdateUserById(
		ctx context.Context,
		request events.APIGatewayProxyRequest,
	) (
		events.APIGatewayProxyResponse,
		error,
	)
	GetAccessTokenViaRefreshToken(
		ctx context.Context,
		request events.APIGatewayProxyRequest,
	) (
		events.APIGatewayProxyResponse,
		error,
	)
}

type handler struct {
	service    Service
	repository Repository
	logger     *zap.SugaredLogger
	validate   *validator.Validate
}

func NewHandler(
	service Service,
	repository Repository,
	logger *zap.SugaredLogger,
	validate *validator.Validate,
) Handler {
	return &handler{
		service:    service,
		repository: repository,
		logger:     logger,
		validate:   validate,
	}
}

func (h *handler) CreateUser(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
) {
	var (
		err error
		log = h.logger
	)

	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	var registerPayload *RegisterPayload
	err = json.Unmarshal([]byte(request.Body), &registerPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	err = h.validate.Struct(registerPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.service.Register(ctx, registerPayload)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	var responseBody []byte
	responseBody, err = json.Marshal(&tokens)
	if err != nil {
		cerr := cerror.ErrorJsonMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	log.Info(logger.LoggerEventFinished)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusCreated,
		Headers: map[string]string{
			HeaderContentType: MIMEApplicationJson,
		},
		Body: string(responseBody),
	}, nil
}

func (h *handler) Login(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
) {
	var (
		err error
		log = h.logger
	)

	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	var loginPayload *LoginPayload
	err = json.Unmarshal([]byte(request.Body), &loginPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	err = h.validate.Struct(loginPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.service.Login(ctx, loginPayload)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	var responseBody []byte
	responseBody, err = json.Marshal(&tokens)
	if err != nil {
		cerr := cerror.ErrorJsonMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	h.logger.Info(logger.LoggerEventFinished)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			HeaderContentType: MIMEApplicationJson,
		},
		Body: string(responseBody),
	}, nil
}

func (h *handler) GetUserById(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
) {
	var (
		err error
		log = h.logger
	)

	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}

	var requestBody *GetUserByIdPayload
	err = json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	userId := requestBody.UserId
	log = log.With(
		zap.String("userId", userId),
	)
	ctx = logger.InjectContext(ctx, log)

	err = h.validate.Struct(requestBody)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	var userDocument *Table
	userDocument, err = h.repository.FindUserWithId(ctx, userId)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	var payload []byte
	payload, err = json.Marshal(userDocument)
	if err != nil {
		cerr := cerror.ErrorJsonMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	log.Info(logger.LoggerEventFinished)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			HeaderContentType: MIMEApplicationJson,
		},
		Body:            string(payload),
		IsBase64Encoded: false,
	}, nil
}

func (h *handler) UpdateUserById(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
) {
	var (
		err error
		log = h.logger
	)

	lambdaContext, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(
			zap.String("requestId", lambdaContext.AwsRequestID),
		)
	}

	var requestPayload *UpdateUserPayload
	err = json.Unmarshal([]byte(request.Body), &requestPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	userId := requestPayload.UserId
	log = log.With(
		zap.String("userId", userId),
	)
	ctx = logger.InjectContext(ctx, log)

	err = h.validate.Struct(requestPayload)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.service.UpdateUserById(ctx, userId, requestPayload)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	var responseBody []byte
	responseBody, err = json.Marshal(tokens)
	if err != nil {
		cerr := cerror.ErrorJsonMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	log.Info(logger.LoggerEventFinished)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			HeaderContentType: MIMEApplicationJson,
		},
		Body: string(responseBody),
	}, nil
}

func (h *handler) GetAccessTokenViaRefreshToken(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
) {
	var (
		err error
		log = h.logger
	)

	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	var requestBody *GetAccessTokenViaRefreshTokenPayload
	err = json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	err = h.validate.Struct(requestBody)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	var accessToken *AccessTokenPayload
	accessToken, err = h.service.GetAccessTokenByRefreshToken(
		ctx,
		requestBody.UserId,
		requestBody.RefreshToken,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	var responseBody []byte
	responseBody, err = json.Marshal(&accessToken)
	if err != nil {
		cerr := cerror.ErrorJsonMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return events.APIGatewayProxyResponse{}, cerr
	}

	log.Info(logger.LoggerEventFinished)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			HeaderContentType: MIMEApplicationJson,
		},
		Body: string(responseBody),
	}, nil
}
