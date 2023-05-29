package user

import (
	"net/http"

	"github.com/go-playground/validator"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"

	"user-api/pkg/cerror"
	"user-api/pkg/logger"
	"user-api/pkg/server"
)

type handler struct {
	userService Service
}

func (h *handler) RegisterRoutes(app *fiber.App) {
	app.Post("/user", h.Register)
	app.Get("/user/email/:email/password/:password", h.Login)
	app.Get("/user/:userId/refreshToken/:refreshToken", h.GetAccessToken)
}

func NewHandler(userService Service) server.Handler {
	return &handler{
		userService: userService,
	}
}

func (h *handler) Register(ctx *fiber.Ctx) error {
	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "registerWithEmail"))
	logger.InjectContext(ctx.Context(), log)

	var user UserPayload
	err := ctx.BodyParser(&user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
			zap.Any("body", user),
		).SetSeverity(zap.WarnLevel)
	}

	validate := validator.New()
	err = validate.Struct(user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
		).SetSeverity(zap.WarnLevel)
	}

	tokens, err := h.userService.Register(ctx.Context(), &user)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(fiber.StatusCreated).
		JSON(tokens)
}

func (h *handler) Login(ctx *fiber.Ctx) error {
	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "loginWithEmail"))
	logger.InjectContext(ctx.Context(), log)

	tokens, err := h.userService.Login(ctx.Context(), &UserPayload{
		Email:    ctx.Params("email"),
		Password: ctx.Params("password"),
	})
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(http.StatusOK).
		JSON(tokens)
}

func (h *handler) GetAccessToken(ctx *fiber.Ctx) error {
	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "getAccessToken"))
	logger.InjectContext(ctx.Context(), log)

	userId := ctx.Params("userId")
	refreshToken := ctx.Params("refreshToken")
	accessToken, err := h.userService.GetAccessToken(ctx.Context(), userId, refreshToken)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}
