package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-lambda-go/events"
	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

type Handler interface {
	RegisterRoutes(app *fiber.App)
}

type Server interface {
	GetFiberInstance() *fiber.App
	Start() error
	Shutdown() error
	RegisterRoutes()
	LambdaProxyHandler(
		ctx context.Context,
		req events.APIGatewayProxyRequest,
	) (events.APIGatewayProxyResponse, error)
}

type server struct {
	serverPort         string
	handlers           []Handler
	fiber              *fiber.App
	fiberLambdaAdapter *fiberadapter.FiberLambda
}

func NewServer(config *config.Config, handlers []Handler) Server {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		ErrorHandler:          cerror.Middleware,
	})
	fiberLambdaAdapter := fiberadapter.New(app)
	return &server{
		fiber:              app,
		handlers:           handlers,
		serverPort:         config.ServerPort,
		fiberLambdaAdapter: fiberLambdaAdapter,
	}
}

func (server *server) Start() error {
	shutdownChannel := make(chan os.Signal, 1)
	signal.Notify(shutdownChannel, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-shutdownChannel
		_ = server.fiber.Shutdown()
	}()

	serverAddress := fmt.Sprintf(":%s", server.serverPort)
	return server.fiber.Listen(serverAddress)
}

func (server *server) Shutdown() error {
	return server.fiber.Shutdown()
}

func (server *server) GetFiberInstance() *fiber.App {
	return server.fiber
}

func (server *server) RegisterRoutes() {
	for _, handler := range server.handlers {
		handler.RegisterRoutes(server.fiber)
	}
}

func (server *server) LambdaProxyHandler(
	ctx context.Context,
	req events.APIGatewayProxyRequest,
) (events.APIGatewayProxyResponse, error) {
	return server.fiberLambdaAdapter.ProxyWithContext(ctx, req)
}
