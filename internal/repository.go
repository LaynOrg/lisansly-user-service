package user

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/goccy/go-json"
	"go.uber.org/zap"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

type Repository interface {
	InsertUser(ctx context.Context, user *Table) *cerror.CustomError
	FindUserWithId(ctx context.Context, userId string) (*Table, *cerror.CustomError)
	FindUserWithEmail(ctx context.Context, email string) (*Table, *cerror.CustomError)
	InsertRefreshTokenHistory(ctx context.Context, refreshTokenHistory *RefreshTokenHistoryTable) *cerror.CustomError
	FindRefreshTokenWithUserId(ctx context.Context, userId string) (*RefreshTokenHistoryTable, *cerror.CustomError)
	UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) *cerror.CustomError
	InsertIdentityVerificationHistory(
		ctx context.Context, identityVerification *IdentityVerificationTable,
	) *cerror.CustomError
	SendEmailVerificationMessage(
		ctx context.Context, verificationSqsMessageBody *EmailVerificationSqsMessageBody,
	) *cerror.CustomError
}

type repository struct {
	dynamodbClient *dynamodb.Client
	dynamodbConfig *config.DynamoDbConfig
	sqsClient      *sqs.Client
	sqsConfig      *config.SQSConfig
}

func NewRepository(
	dynamodbClient *dynamodb.Client,
	dynamodbConfig *config.DynamoDbConfig,
	sqsClient *sqs.Client,
	sqsConfig *config.SQSConfig,
) Repository {
	return &repository{
		dynamodbClient: dynamodbClient,
		dynamodbConfig: dynamodbConfig,
		sqsClient:      sqsClient,
		sqsConfig:      sqsConfig,
	}
}

func (r *repository) InsertUser(ctx context.Context, user *Table) *cerror.CustomError {
	var err error

	var userItem map[string]dynamodbTypes.AttributeValue
	userItem, err = attributevalue.MarshalMap(user)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal user",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	var userUniquenessItem map[string]dynamodbTypes.AttributeValue
	userUniquenessItem, err = attributevalue.MarshalMap(&UniquenessTable{
		Unique: user.Email,
		Type:   IdentityEmail,
	})
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal user's uniqueness",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	var userIdExpression expression.Expression
	userIdExpression, err = expression.
		NewBuilder().
		WithCondition(
			expression.Name("id").AttributeNotExists(),
		).
		Build()
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while build user id expression",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	var userEmailExpression expression.Expression
	userEmailExpression, err = expression.
		NewBuilder().
		WithCondition(
			expression.Name("unique").AttributeNotExists(),
		).
		Build()
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while build email expression",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	userTableName := aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserTable])
	userUniquenessTableName := aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserUniquenessTable])
	_, err = r.dynamodbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []dynamodbTypes.TransactWriteItem{
			{
				Put: &dynamodbTypes.Put{
					Item:                     userItem,
					ConditionExpression:      userIdExpression.Condition(),
					ExpressionAttributeNames: userIdExpression.Names(),
					TableName:                userTableName,
				},
			},
			{
				Put: &dynamodbTypes.Put{
					Item:                     userUniquenessItem,
					ConditionExpression:      userEmailExpression.Condition(),
					ExpressionAttributeNames: userEmailExpression.Names(),
					TableName:                userUniquenessTableName,
				},
			},
		},
	})
	if err != nil {
		var alreadyExistError *dynamodbTypes.TransactionCanceledException
		ok := errors.As(err, &alreadyExistError)
		if ok {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusConflict,
				LogMessage:     "user already exist",
				LogSeverity:    zap.WarnLevel,
			}
		}

		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while insert user",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) InsertRefreshTokenHistory(
	ctx context.Context,
	refreshTokenHistory *RefreshTokenHistoryTable,
) *cerror.CustomError {
	var err error

	var refreshTokenHistoryItem map[string]dynamodbTypes.AttributeValue
	refreshTokenHistoryItem, err = attributevalue.MarshalMap(refreshTokenHistory)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal refresh token history item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	tableName := aws.String(r.dynamodbConfig.Tables[config.DynamoDbRefreshTokenHistoryTable])
	_, err = r.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		Item:      refreshTokenHistoryItem,
		TableName: tableName,
	})
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while insert refresh token history item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) FindUserWithId(ctx context.Context, userId string) (*Table, *cerror.CustomError) {
	var err error

	condition := expression.Key("id").Equal(expression.Value(userId))

	var expr expression.Expression
	expr, err = expression.
		NewBuilder().
		WithKeyCondition(condition).
		Build()
	if err != nil {
		cerr := cerror.ErrorBuildExpression
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var result *dynamodb.QueryOutput
	result, err = r.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		TableName:                 aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserTable]),
	})
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while getting user",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	if len(result.Items) == 0 {
		return nil, cerror.ErrorUserNotFound
	}

	var user *Table
	err = attributevalue.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshalling item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return user, nil
}

func (r *repository) FindUserWithEmail(ctx context.Context, email string) (*Table, *cerror.CustomError) {
	var err error

	condition := expression.Name("email").Equal(expression.Value(email))

	var expr expression.Expression
	expr, err = expression.
		NewBuilder().
		WithFilter(condition).
		Build()
	if err != nil {
		cerr := cerror.ErrorBuildExpression
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var result *dynamodb.ScanOutput
	result, err = r.dynamodbClient.Scan(ctx, &dynamodb.ScanInput{
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		TableName:                 aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserTable]),
	})
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while getting user",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	if len(result.Items) == 0 {
		cerr := cerror.ErrorUserNotFound
		cerr.LogSeverity = zap.WarnLevel
		return nil, cerr
	}

	var user *Table
	err = attributevalue.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal user",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return user, nil
}

func (r *repository) FindRefreshTokenWithUserId(
	ctx context.Context, userId string,
) (*RefreshTokenHistoryTable, *cerror.CustomError) {
	var err error

	condition := expression.Name("userId").Equal(expression.Value(userId))

	var expr expression.Expression
	expr, err = expression.
		NewBuilder().
		WithFilter(condition).
		Build()
	if err != nil {
		cerr := cerror.ErrorBuildExpression
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var result *dynamodb.ScanOutput
	result, err = r.dynamodbClient.Scan(ctx, &dynamodb.ScanInput{
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		TableName:                 aws.String(r.dynamodbConfig.Tables[config.DynamoDbRefreshTokenHistoryTable]),
	})
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while getting item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	if len(result.Items) == 0 {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusNotFound,
			LogMessage:     "refresh token not found",
			LogSeverity:    zap.ErrorLevel,
		}
	}

	var refreshToken *RefreshTokenHistoryTable
	err = attributevalue.UnmarshalMap(result.Items[0], &refreshToken)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshalling",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return refreshToken, nil
}

func (r *repository) UpdateUserById(
	ctx context.Context, userId string, updateUserPayload *UpdateUserPayload,
) *cerror.CustomError {
	var (
		err                 error
		userTable           = aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserTable])
		userUniquenessTable = aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserUniquenessTable])
		userIdKey           = map[string]dynamodbTypes.AttributeValue{
			"id": &dynamodbTypes.AttributeValueMemberS{Value: userId},
		}
	)

	updateExpression, cerr := r.buildUpdateExpression(updateUserPayload)
	if err != nil {
		return cerr
	}

	if updateUserPayload.Email != "" {
		var result *dynamodb.GetItemOutput
		result, err = r.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
			Key:       userIdKey,
			TableName: userTable,
		})
		if err != nil {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while find user with key",
				LogSeverity:    zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}

		if result.Item == nil {
			return cerror.ErrorUserNotFound
		}

		var userInDatabase *Table
		err = attributevalue.UnmarshalMap(result.Item, &userInDatabase)
		if err != nil {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while unmarshalling user item",
				LogSeverity:    zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}

		var emailUniquenessItem map[string]dynamodbTypes.AttributeValue
		emailUniquenessItem, err = attributevalue.MarshalMap(&UniquenessTable{
			Unique: updateUserPayload.Email,
			Type:   IdentityEmail,
		})
		if err != nil {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while marshalling email uniqueness item",
				LogSeverity:    zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}

		_, err = r.dynamodbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []dynamodbTypes.TransactWriteItem{
				{
					Update: &dynamodbTypes.Update{
						Key:                       userIdKey,
						TableName:                 userTable,
						UpdateExpression:          updateExpression.Update(),
						ExpressionAttributeNames:  updateExpression.Names(),
						ExpressionAttributeValues: updateExpression.Values(),
					},
				},
				{
					Delete: &dynamodbTypes.Delete{
						TableName: userUniquenessTable,
						Key: map[string]dynamodbTypes.AttributeValue{
							"unique": &dynamodbTypes.AttributeValueMemberS{
								Value: userInDatabase.Email,
							},
						},
					},
				},
				{
					Put: &dynamodbTypes.Put{
						Item:      emailUniquenessItem,
						TableName: userUniquenessTable,
					},
				},
			},
		})
		if err != nil {
			var emailAlreadyExist *dynamodbTypes.ConditionalCheckFailedException
			ok := errors.As(err, &emailAlreadyExist)
			if ok {
				return &cerror.CustomError{
					HttpStatusCode: http.StatusConflict,
					LogMessage:     "email address already exist in user table",
					LogSeverity:    zap.WarnLevel,
					LogFields: []zap.Field{
						zap.Error(emailAlreadyExist),
					},
				}
			}

			return &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while update user",
				LogSeverity:    zap.ErrorLevel,
				LogFields: []zap.Field{
					zap.Error(err),
				},
			}
		}
	} else {
		_, err = r.dynamodbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			Key:                       userIdKey,
			UpdateExpression:          updateExpression.Update(),
			ExpressionAttributeNames:  updateExpression.Names(),
			ExpressionAttributeValues: updateExpression.Values(),
			ReturnValues:              dynamodbTypes.ReturnValueNone,
			TableName:                 userTable,
		})
		if err != nil {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while update user",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	return nil
}

func (r *repository) InsertIdentityVerificationHistory(
	ctx context.Context, identityVerification *IdentityVerificationTable,
) *cerror.CustomError {
	var err error

	var identityVerificationItem map[string]dynamodbTypes.AttributeValue
	identityVerificationItem, err = attributevalue.MarshalMap(identityVerification)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal identity verification history item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	tableName := aws.String(r.dynamodbConfig.Tables[config.DynamoDbIdentityVerificationHistoryTable])
	_, err = r.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		Item:      identityVerificationItem,
		TableName: tableName,
	})
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while insert identity verification history item",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) SendEmailVerificationMessage(
	ctx context.Context, verificationSqsMessageBody *EmailVerificationSqsMessageBody,
) *cerror.CustomError {
	var err error

	var messageBodyBytes []byte
	messageBodyBytes, err = json.Marshal(verificationSqsMessageBody)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal identity verification email message",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	queueUrl := r.sqsConfig.EmailVerificationQueueUrl
	_, err = r.sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:     queueUrl,
		DelaySeconds: 10,
		MessageBody:  aws.String(string(messageBodyBytes)),
		MessageAttributes: map[string]sqsTypes.MessageAttributeValue{
			"From": {
				DataType:    aws.String("String"),
				StringValue: aws.String("UserAPI"),
			},
			"To": {
				DataType:    aws.String("String"),
				StringValue: aws.String("EmailAPI"),
			},
		},
	})
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while send message to email queue",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) buildUpdateExpression(
	updateUserPayload *UpdateUserPayload,
) (expression.Expression, *cerror.CustomError) {
	var (
		err           error
		updateBuilder expression.UpdateBuilder
	)

	if updateUserPayload.Name != "" {
		updateBuilder = updateBuilder.Set(
			expression.Name("name"),
			expression.Value(updateUserPayload.Name),
		)
	}

	if updateUserPayload.Password != "" {
		updateBuilder = updateBuilder.Set(
			expression.Name("password"),
			expression.Value(updateUserPayload.Password),
		)
	}

	if updateUserPayload.Email != "" {
		updateBuilder = updateBuilder.Set(
			expression.Name("email"),
			expression.Value(updateUserPayload.Email),
		)
	}

	var updateExpression expression.Expression
	updateExpression, err = expression.
		NewBuilder().
		WithUpdate(updateBuilder).
		Build()
	if err != nil {
		cerr := cerror.ErrorBuildExpression
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return expression.Expression{}, cerr
	}

	return updateExpression, nil
}
