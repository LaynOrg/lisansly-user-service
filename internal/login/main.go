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
	"user-api/pkg/config"
	"user-api/pkg/jwt_generator"
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
	var jwtConfig *config.JwtConfig
	jwtConfig, err = config.ReadJwtConfig()
	if err != nil {
		log.Panic(err)
	}

	var jwtGenerator jwt_generator.JwtGenerator
	jwtGenerator, err = jwt_generator.NewJwtGenerator(jwtConfig)
	if err != nil {
		log.Panic(err)
	}

	service := user.NewService(repository, jwtGenerator)
	handler := user.NewHandler(
		service,
		nil,
		log,
		validator.New(),
	)

	lambda.Start(handler.Login)
}
