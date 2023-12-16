package config

// #nosec
const (
	EnvironmentVariableNotDefined = "%s variable is not defined"

	DynamoDbUserTable                        = "DYNAMODB_USER_TABLE"
	DynamoDbUserUniquenessTable              = "DYNAMODB_USER_UNIQUENESS_TABLE"
	DynamoDbRefreshTokenHistoryTable         = "DYNAMODB_REFRESH_TOKEN_HISTORY_TABLE"
	DynamoDbIdentityVerificationHistoryTable = "DYNAMODB_IDENTITY_VERIFICATION_HISTORY_TABLE"

	AwsAccountId                 = "AWS_ACCOUNT_ID"
	SQSEmailVerificationQueueUrl = "SQS_EMAIL_VERIFICATION_QUEUE_URL"

	JwtPrivateKey = "JWT_PRIVATE_KEY"
	JwtPublicKey  = "JWT_PUBLIC_KEY"
)

type DynamoDbConfig struct {
	Tables map[string]string
}

type SQSConfig struct {
	AwsAccountId              string
	EmailVerificationQueueUrl *string
}

type JwtConfig struct {
	PrivateKey []byte
	PublicKey  []byte
}
