package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	user "user-api/internal"
	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

func main() {
	var err error

	logWithProductionConfig, _ := zap.NewProduction()
	log := logWithProductionConfig.Sugar()
	defer func(log *zap.SugaredLogger) {
		err := log.Sync()
		if err != nil {
			panic(err)
		}
	}(log)

	var dynamoDbConfig *config.DynamoDbConfig
	dynamoDbConfig, err = config.ReadDynamoDbConfig()
	if err != nil {
		log.Panic(err)
	}

	var cfg aws.Config
	cfg, err = awsCfg.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Panic(err)
	}

	dynamodbClient := dynamodb.NewFromConfig(cfg)
	repository := user.NewRepository(dynamodbClient, dynamoDbConfig)
	handler := user.NewHandler(
		nil,
		repository,
		validator.New(),
	)

	lambda.Start(
		cerror.WithMiddleware(
			log,
			cerror.ErrorHandler,
			handler.GetUserById,
		),
	)
}
