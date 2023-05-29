package main

import (
	"os"
	"path/filepath"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"

	"user-api/internal/user"
	"user-api/pkg/config"
	"user-api/pkg/jwt_generator"
	"user-api/pkg/logger"
	"user-api/pkg/path"
	"user-api/pkg/server"
)

func main() {
	log := logger.NewLogger()

	isAtRemote := os.Getenv(config.IsAtRemote)
	if isAtRemote == "" {
		rootDirectory := path.GetRootDirectory()
		dotenvPath := filepath.Join(rootDirectory, ".env")
		err := godotenv.Load(dotenvPath)
		if err != nil {
			panic(err)
		}
	}

	cfg, err := config.ReadConfig()
	if err != nil {
		panic(err)
	}
	cfg.Print()

	var handlers []server.Handler

	jwtFactory, err := jwt_generator.NewJwtGenerator([]byte("secret-key"))
	if err != nil {
		panic(err)
	}

	userRepository := user.NewRepository(cfg)
	userService := user.NewService(userRepository, jwtFactory)
	userHandler := user.NewHandler(userService)

	handlers = append(handlers, userHandler)
	srv := server.NewServer(cfg, handlers)

	logMiddleware := logger.Middleware(log)
	app := srv.GetFiberInstance()
	app.Use(logMiddleware)
	app.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).SendString("OK")
	})

	if isAtRemote == "" {
		err = srv.Start()
		if err != nil {
			panic(err)
		}
	} else {
		lambda.Start(srv.LambdaProxyHandler)
	}
}
