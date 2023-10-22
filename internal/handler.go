package user

import (
	"context"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"user-service/pkg/cerror"
	"user-service/pkg/jwt_generator"
	"user-service/pkg/logger"
)

type Handler interface {
	Register(ctx context.Context, request *RegisterPayload) (*jwt_generator.Tokens, error)
	Login(ctx context.Context, request *LoginPayload) (*jwt_generator.Tokens, error)
	GetUserById(ctx context.Context, request *GetUserByIdPayload) (*Table, error)
	UpdateUserById(ctx context.Context, request *UpdateUserPayload) (*jwt_generator.Tokens, error)
	GetAccessTokenViaRefreshToken(
		ctx context.Context,
		request *GetAccessTokenViaRefreshTokenPayload,
	) (*AccessTokenPayload, error)
}

type handler struct {
	service    Service
	repository Repository
	validate   *validator.Validate
}

func NewHandler(
	service Service,
	repository Repository,
) Handler {
	return &handler{
		service:    service,
		repository: repository,
		validate:   validator.New(),
	}
}

func (h handler) Register(ctx context.Context, request *RegisterPayload) (*jwt_generator.Tokens, error) {
	log := logger.FromContext(ctx)
	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	err := h.validate.Struct(request)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerror.ErrorHandler(log, cerr)
	}

	tokens, cerr := h.service.Register(ctx, request)
	if cerr != nil {
		return nil, cerror.ErrorHandler(log, cerr)
	}

	log.Info(logger.LoggerEventFinished)
	return tokens, nil
}

func (h handler) Login(ctx context.Context, request *LoginPayload) (*jwt_generator.Tokens, error) {
	log := logger.FromContext(ctx)
	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	err := h.validate.Struct(request)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerror.ErrorHandler(log, cerr)
	}

	tokens, cerr := h.service.Login(ctx, request)
	if cerr != nil {
		return nil, cerror.ErrorHandler(log, cerr)
	}

	log.Info(logger.LoggerEventFinished)
	return tokens, nil
}

func (h handler) GetUserById(ctx context.Context, request *GetUserByIdPayload) (*Table, error) {
	log := logger.FromContext(ctx)
	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}

	userId := request.UserId
	log = log.With(zap.String("userId", userId))
	ctx = logger.InjectContext(ctx, log)

	err := h.validate.Struct(request)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerror.ErrorHandler(log, cerr)
	}

	userDocument, cerr := h.repository.FindUserWithId(ctx, userId)
	if cerr != nil {
		return nil, cerror.ErrorHandler(log, cerr)
	}

	log.Info(logger.LoggerEventFinished)
	return userDocument, nil
}

func (h handler) UpdateUserById(ctx context.Context, request *UpdateUserPayload) (*jwt_generator.Tokens, error) {
	log := logger.FromContext(ctx)
	lambdaContext, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(
			zap.String("requestId", lambdaContext.AwsRequestID),
		)
	}
	ctx = logger.InjectContext(ctx, log)

	userId := request.UserId
	log = log.With(
		zap.String("userId", userId),
	)
	ctx = logger.InjectContext(ctx, log)

	err := h.validate.Struct(request)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerror.ErrorHandler(log, cerr)
	}

	tokens, cerr := h.service.UpdateUserById(ctx, userId, request)
	if cerr != nil {
		return nil, cerror.ErrorHandler(log, cerr)
	}

	log.Info(logger.LoggerEventFinished)
	return tokens, nil
}

func (h handler) GetAccessTokenViaRefreshToken(
	ctx context.Context,
	request *GetAccessTokenViaRefreshTokenPayload,
) (*AccessTokenPayload, error) {
	log := logger.FromContext(ctx)
	lc, ok := lambdacontext.FromContext(ctx)
	if ok {
		log = log.With(zap.String("requestId", lc.AwsRequestID))
	}
	ctx = logger.InjectContext(ctx, log)

	err := h.validate.Struct(request)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerror.ErrorHandler(log, cerr)
	}

	accessToken, cerr := h.service.GetAccessTokenByRefreshToken(
		ctx,
		request.UserId,
		request.RefreshToken,
	)
	if cerr != nil {
		return nil, cerror.ErrorHandler(log, cerr)
	}

	log.Info(logger.LoggerEventFinished)
	return accessToken, nil
}
