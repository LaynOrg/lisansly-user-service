package user

import (
	"net/http"

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
	AuthenticationMiddleware(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	UpdateUserById(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error
}

type handler struct {
	userService Service
	validate    *validator.Validate
}

func (h *handler) RegisterRoutes(app *fiber.App) {
	app.Post("/user", h.Register)
	app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)
	app.Get("/user/email/:email/password/:password", h.Login)
	app.Get("/user/:userId/refreshToken/:refreshToken", h.GetAccessTokenByRefreshToken)
}

func NewHandler(userService Service) Handler {
	validate := validator.New()
	return &handler{
		userService: userService,
		validate:    validate,
	}
}

func (h *handler) AuthenticationMiddleware(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "authenticationMiddleware"))
	logger.InjectContext(ctx.Context(), log)

	requestHeaders := ctx.GetReqHeaders()
	authorizationHeader := requestHeaders[fiber.HeaderAuthorization]
	authorizationHeaderLength := len([]rune(authorizationHeader))
	if authorizationHeaderLength == 0 {
		return cerror.NewError(
			http.StatusUnauthorized,
			"access token not found in authorization header",
		).SetSeverity(zapcore.WarnLevel)
	}

	accessToken := authorizationHeader[7:authorizationHeaderLength]
	var jwtClaims *jwt_generator.Claims
	jwtClaims, err = h.userService.VerifyAccessToken(ctx.Context(), accessToken)
	if err != nil {
		return err
	}

	userId := jwtClaims.Subject
	ctx.Locals(ContextKeyUserId, userId)

	log.With(
		zap.String("authorizationHeader", authorizationHeader),
	).Info("authenticated")
	return ctx.Next()
}

func (h *handler) Register(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "register"))
	logger.InjectContext(ctx.Context(), log)

	var user *RegisterPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
			zap.Any("body", ctx.Body()),
		).SetSeverity(zap.WarnLevel)
	}

	err = h.validate.Struct(user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
		).SetSeverity(zap.WarnLevel)
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.Register(ctx.Context(), user)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(fiber.StatusCreated).
		JSON(tokens)
}

func (h *handler) UpdateUserById(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "updateUserById"))
	logger.InjectContext(ctx.Context(), log)

	var user *UpdateUserPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
			zap.Any("body", ctx.Body()),
		).SetSeverity(zap.WarnLevel)
	}

	err = h.validate.Struct(user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request body",
			zap.Any("body", ctx.Body()),
		).SetSeverity(zap.WarnLevel)
	}

	userId := ctx.Locals(ContextKeyUserId).(string)
	if userId == "" {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"UserId context is empty",
		)
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.UpdateUserById(ctx.Context(), userId, user)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(fiber.StatusOK).
		JSON(tokens)
}

func (h *handler) Login(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "login"))
	logger.InjectContext(ctx.Context(), log)

	user := &LoginPayload{
		Email:    ctx.Params("email"),
		Password: ctx.Params("password"),
	}

	err = h.validate.Struct(user)
	if err != nil {
		return cerror.NewError(
			fiber.StatusBadRequest,
			"malformed request params",
		).SetSeverity(zapcore.WarnLevel)
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userService.Login(ctx.Context(), user)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.
		Status(http.StatusOK).
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

	log.Info("event successfully finished")
	return ctx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}
