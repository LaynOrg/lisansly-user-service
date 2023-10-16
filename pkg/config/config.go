package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
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

	identityVerificationHistoryTable := os.Getenv(DynamoDbIdentityVerificationHistoryTable)
	if identityVerificationHistoryTable == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, DynamoDbIdentityVerificationHistoryTable)
	}

	return &DynamoDbConfig{
		Tables: map[string]string{
			DynamoDbUserTable:                        userTable,
			DynamoDbUserUniquenessTable:              userUniquenessTable,
			DynamoDbRefreshTokenHistoryTable:         refreshTokenHistoryTable,
			DynamoDbIdentityVerificationHistoryTable: identityVerificationHistoryTable,
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

	emailVerificationQueueUrl := os.Getenv(SQSEmailVerificationQueueUrl)
	if emailVerificationQueueUrl == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, SQSEmailVerificationQueueUrl)
	}

	return &SQSConfig{
		AwsAccountId:              awsAccountId,
		EmailVerificationQueueUrl: aws.String(emailVerificationQueueUrl),
	}, nil
}
