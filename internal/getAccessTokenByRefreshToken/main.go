package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.uber.org/zap"

	user "user-service/internal"
	"user-service/pkg/config"
	"user-service/pkg/jwt_generator"
)

func main() {
	var err error

	logWithProductionConfig, _ := zap.NewProduction()
	defer logWithProductionConfig.Sync()
	log := logWithProductionConfig.Sugar()

	var dynamodbConfig *config.DynamoDbConfig
	dynamodbConfig, err = config.ReadDynamoDbConfig()
	if err != nil {
		log.Panic(err)
	}

	var cfg aws.Config
	cfg, err = awsCfg.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Panic(err)
	}

	dynamodbClient := dynamodb.NewFromConfig(cfg)
	repository := user.NewRepository(dynamodbClient, dynamodbConfig, nil, nil)
	if err != nil {
		log.Panic(err)
	}

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
	)

	lambda.Start(handler.GetAccessTokenViaRefreshToken)
}
