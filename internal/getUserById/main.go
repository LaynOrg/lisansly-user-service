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
)

func main() {
	var err error

	logWithProductionConfig, _ := zap.NewProduction()
	defer logWithProductionConfig.Sync()
	log := logWithProductionConfig.Sugar()

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
	repository := user.NewRepository(dynamodbClient, dynamoDbConfig, nil, nil)
	handler := user.NewHandler(
		nil,
		repository,
	)

	lambda.Start(handler.GetUserById)
}
