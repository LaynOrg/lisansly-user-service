package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	user "user-api/internal"
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

	mongoClient := setupMongodbClient(cfg)
	userRepository := user.NewRepository(mongoClient, cfg)
	userService := user.NewService(userRepository, jwtFactory)
	userHandler := user.NewHandler(userService)

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

func setupMongodbClient(cfg *config.Config) *mongo.Client {
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
		panic(err)
	}
	defer func(mongoClient *mongo.Client, ctx context.Context) {
		err := mongoClient.Disconnect(ctx)
		if err != nil {
			panic(err)
		}
	}(mongodbClient, ctx)

	return mongodbClient
}
