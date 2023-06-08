package user

import (
	"net/http"

	"github.com/go-playground/validator"
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
	Login(ctx *fiber.Ctx) error
	GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error
}

type handler struct {
	userService Service
}

func (h *handler) RegisterRoutes(app *fiber.App) {
	app.Post("/user", h.Register)
	app.Get("/user/identifier/:identifier/password/:password", h.Login)
	app.Get("/user/:userId/refreshToken/:refreshToken", h.GetAccessTokenByRefreshToken)
}

func NewHandler(userService Service) Handler {
	return &handler{
		userService: userService,
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

	log.With(zap.String("authorizationHeader", authorizationHeader))
	logger.InjectContext(ctx.Context(), log)

	accessToken := authorizationHeader[7:authorizationHeaderLength]
	err = h.userService.VerifyAccessToken(ctx.Context(), accessToken)
	if err != nil {
		return err
	}

	log.Info("event successfully finished")
	return ctx.Next()
}

func (h *handler) Register(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "register"))
	logger.InjectContext(ctx.Context(), log)

	var user *UserRegisterPayload
	err = ctx.BodyParser(&user)
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

func (h *handler) Login(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "login"))
	logger.InjectContext(ctx.Context(), log)

	identifier := ctx.Params("identifier")
	password := ctx.Params("password")

	validate := validator.New()
	err = validate.Var(identifier, "required,email")

	user := &UserLoginPayload{}
	if err != nil {
		user.Name = identifier
	} else {
		user.Email = identifier
	}
	user.Password = password

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
