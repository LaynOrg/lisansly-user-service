package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"os"

	user "user-api/internal"
	"user-api/pkg/config"
	"user-api/pkg/jwt_generator"
	"user-api/pkg/logger"
	"user-api/pkg/server"
)

func main() {
	logWithProductionConfig, _ := zap.NewProduction()
	log := logWithProductionConfig.Sugar()
	defer func(l *zap.Logger) {
		err := l.Sync()
		if err != nil {
			panic(err)
		}
	}(logWithProductionConfig)

	isAtRemote := os.Getenv(config.IsAtRemote)
	if isAtRemote == "" {
		err := godotenv.Load()
		if err != nil {
			log.Fatalw(
				"failed to load .env file",
				zap.Error(err),
			)
		}
	}

	cfg, err := config.ReadConfig()
	if err != nil {
		panic(err)
	}
	cfg.Print()

	var jwtGenerator jwt_generator.JwtGenerator
	jwtGenerator, err = jwt_generator.NewJwtGenerator(cfg.Jwt)
	if err != nil {
		log.Fatalw(
			"failed to create jwt generator",
			zap.Error(err),
		)
	}

	ctx := context.Background()
	mongoDbClient, err := setupMongodbClient(cfg)
	if err != nil {
		log.Fatalw(
			"failed to setup mongodb client",
			zap.Error(err),
		)
	}

	defer func(client *mongo.Client, ctx context.Context) {
		err := client.Disconnect(ctx)
		if err != nil {
			log.Fatalw(
				"failed to disconnect mongodb client",
				zap.Error(err),
			)
		}
	}(mongoDbClient, ctx)

	userRepository := user.NewRepository(mongoDbClient, cfg.Mongodb)
	userService := user.NewService(userRepository, jwtGenerator)
	userHandler := user.NewHandler(userService, nil)

	var handlers []server.Handler
	handlers = append(handlers, userHandler)
	srv := server.NewServer(cfg, handlers)

	logMiddleware := logger.Middleware(log)
	app := srv.GetFiberInstance()
	app.Use(cors.New())
	app.Use(logMiddleware)
	app.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).SendString("OK")
	})

	srv.RegisterRoutes()

	if isAtRemote == "" {
		err = srv.Start()
		if err != nil {
			panic(err)
		}
	} else {
		lambda.Start(srv.LambdaProxyHandler)
	}
}

func setupMongodbClient(cfg *config.Config) (*mongo.Client, error) {
	mongodbCredential := options.Credential{
		Username: cfg.Mongodb.Username,
		Password: cfg.Mongodb.Password,
	}
	mongodbServerAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	credentials := options.Client().
		ApplyURI(cfg.Mongodb.Uri).
		SetAuth(mongodbCredential).
		SetServerAPIOptions(mongodbServerAPIOptions)

	ctx := context.Background()
	mongodbClient, err := mongo.Connect(ctx, credentials)
	if err != nil {
		return nil, err
	}

	return mongodbClient, nil
}
