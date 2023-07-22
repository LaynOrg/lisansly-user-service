package user

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"user-api/pkg/cerror"
	"user-api/pkg/jwt_generator"
	"user-api/pkg/logger"
	"user-api/pkg/server"
)

type Handler interface {
	server.Handler
	CreateUser(ctx *fiber.Ctx) error
	UpdateUserById(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error
}

type handler struct {
	userService    Service
	userRepository Repository
	validate       *validator.Validate
}

func (h *handler) RegisterRoutes(app *fiber.App) {
	app.Post("/user", h.CreateUser)
	app.Post("/login", h.Login)
	app.Get("/user/:userId", h.GetUserById)
	app.Patch("/user/:userId", h.UpdateUserById)
	app.Get("/user/:userId/refreshToken/:refreshToken", h.GetAccessTokenByRefreshToken)
}

func NewHandler(userService Service, userRepository Repository) Handler {
	validate := validator.New()
	return &handler{
		userService:    userService,
		userRepository: userRepository,
		validate:       validate,
	}
}

func (h *handler) CreateUser(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "register"))
	logger.InjectContext(ctx.Context(), log)

	var user *RegisterPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}

		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}

		return cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.Register(ctx.Context(), user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusCreated).
		JSON(tokens)
}

func (h *handler) GetUserById(ctx *fiber.Ctx) error {
	var err error

	userId := ctx.Params("userId")
	log := logger.FromContext(ctx.Context()).
		With(
			zap.String("eventName", "getUserById"),
			zap.String("userId", userId),
		)
	logger.InjectContext(ctx.Context(), log)

	var user *Document
	user, err = h.userRepository.FindUserWithId(ctx.Context(), userId)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(user)
}

func (h *handler) UpdateUserById(ctx *fiber.Ctx) error {
	var err error

	userId := ctx.Params("userId")

	log := logger.FromContext(ctx.Context()).
		With(
			zap.String("eventName", "updateUserById"),
			zap.String("userId", userId),
		)
	logger.InjectContext(ctx.Context(), log)

	var user *UpdateUserPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		err = cerror.ErrorBadRequest
		err.(*cerror.CustomError).LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}
		return err
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}

		return cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.UpdateUserById(ctx.Context(), userId, user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(tokens)
}

func (h *handler) Login(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "login"))
	logger.InjectContext(ctx.Context(), log)

	var user *LoginPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}

		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("param", ctx.AllParams()),
		}

		return cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.Login(ctx.Context(), user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(tokens)
}

func (h *handler) GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "getAccessToken"))
	logger.InjectContext(ctx.Context(), log)

	userId := ctx.Params("userId")
	refreshToken := ctx.Params("refreshToken")

	var accessToken string
	accessToken, err = h.userService.GetAccessTokenByRefreshToken(ctx.Context(), userId, refreshToken)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}
