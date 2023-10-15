package config

import (
	"fmt"
	"os"
	"strings"
)

func ReadDynamoDbConfig() (*DynamoDbConfig, error) {
	userTable := os.Getenv(DynamoDbUserTable)
	if userTable == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbUserTable)
	}

	userUniquenessTable := os.Getenv(DynamoDbUserUniquenessTable)
	if userUniquenessTable == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbUserUniquenessTable)
	}

	refreshTokenHistoryTable := os.Getenv(DynamoDbRefreshTokenHistoryTable)
	if refreshTokenHistoryTable == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbRefreshTokenHistoryTable)
	}

	return &DynamoDbConfig{
		Tables: map[string]string{
			DynamoDbUserTable:                userTable,
			DynamoDbUserUniquenessTable:      userUniquenessTable,
			DynamoDbRefreshTokenHistoryTable: refreshTokenHistoryTable,
		},
	}, nil
}

func ReadJwtConfig() (*JwtConfig, error) {
	privateKey := os.Getenv(JwtPrivateKey)
	if privateKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey)
	}
	privateKey = strings.ReplaceAll(privateKey, `\n`, "\n")

	publicKey := os.Getenv(JwtPublicKey)
	if publicKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, JwtPublicKey)
	}
	publicKey = strings.ReplaceAll(publicKey, `\n`, "\n")

	return &JwtConfig{
		PrivateKey: []byte(privateKey),
		PublicKey:  []byte(publicKey),
	}, nil
}

func ReadSqsConfig() (*SQSConfig, error) {
	awsAccountId := os.Getenv(AwsAccountId)
	if awsAccountId == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, AwsAccountId)
	}

	emailQueueName := os.Getenv(SQSEmailVerificationQueueName)
	if emailQueueName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, SQSEmailVerificationQueueName)
	}

	return &SQSConfig{
		AwsAccountId:               awsAccountId,
		EmailVerificationQueueName: emailQueueName,
	}, nil
}
