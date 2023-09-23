package user

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"user-api/pkg/cerror"
	"user-api/pkg/config"
)

type Repository interface {
	InsertUser(ctx context.Context, user *Table) error
	FindUserWithId(ctx context.Context, userId string) (*Table, error)
	FindUserWithEmail(ctx context.Context, email string) (*Table, error)
	InsertRefreshTokenHistory(ctx context.Context, refreshTokenHistory *RefreshTokenHistoryTable) error
	FindRefreshTokenWithUserId(ctx context.Context, userId string) (*RefreshTokenHistoryTable, error)
	UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) error
}

type repository struct {
	dynamodbClient *dynamodb.Client
	dynamodbConfig *config.DynamoDbConfig
}

func NewRepository(
	dynamodbClient *dynamodb.Client,
	dynamodbConfig *config.DynamoDbConfig,
) Repository {
	return &repository{
		dynamodbClient: dynamodbClient,
		dynamodbConfig: dynamodbConfig,
	}
}

func (r *repository) InsertUser(ctx context.Context, user *Table) error {
	var err error

	var userItem map[string]types.AttributeValue
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

	var userUniquenessItem map[string]types.AttributeValue
	userUniquenessItem, err = attributevalue.MarshalMap(&UniquenessTable{
		Unique: user.Email,
		Type:   UniquenessEmail,
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
		TransactItems: []types.TransactWriteItem{
			{
				Put: &types.Put{
					Item:                     userItem,
					ConditionExpression:      userIdExpression.Condition(),
					ExpressionAttributeNames: userIdExpression.Names(),
					TableName:                userTableName,
				},
			},
			{
				Put: &types.Put{
					Item:                     userUniquenessItem,
					ConditionExpression:      userEmailExpression.Condition(),
					ExpressionAttributeNames: userEmailExpression.Names(),
					TableName:                userUniquenessTableName,
				},
			},
		},
	})
	if err != nil {
		var alreadyExistError *types.TransactionCanceledException
		ok := errors.As(err, &alreadyExistError)
		if ok {
			return &cerror.CustomError{
				HttpStatusCode: http.StatusConflict,
				LogMessage:     "user already exist",
				LogSeverity:    zapcore.WarnLevel,
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
) error {
	var err error

	var refreshTokenHistoryItem map[string]types.AttributeValue
	refreshTokenHistoryItem, err = attributevalue.MarshalMap(refreshTokenHistory)
	if err != nil {
		return &cerror.CustomError{
			HttpStatusCode: http.StatusInternalServerError,
			LogMessage:     "error occurred while marshal refresh token history",
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
			LogMessage:     "error occurred while insert refresh token history",
			LogSeverity:    zap.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return nil
}

func (r *repository) FindUserWithId(ctx context.Context, userId string) (*Table, error) {
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
		Limit:                     aws.Int32(1),
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

func (r *repository) FindUserWithEmail(ctx context.Context, email string) (*Table, error) {
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
		Limit:                     aws.Int32(1),
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

func (r *repository) FindRefreshTokenWithUserId(ctx context.Context, userId string) (*RefreshTokenHistoryTable, error) {
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
		Limit:                     aws.Int32(1),
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

func (r *repository) UpdateUserById(ctx context.Context, userId string, updateUserPayload *UpdateUserPayload) error {
	var (
		err                 error
		userTable           = aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserTable])
		userUniquenessTable = aws.String(r.dynamodbConfig.Tables[config.DynamoDbUserUniquenessTable])
		userIdKey           = map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: userId},
		}
	)

	var updateExpression expression.Expression
	updateExpression, err = r.buildUpdateExpression(updateUserPayload)
	if err != nil {
		return err
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

		var emailUniquenessItem map[string]types.AttributeValue
		emailUniquenessItem, err = attributevalue.MarshalMap(&UniquenessTable{
			Unique: updateUserPayload.Email,
			Type:   UniquenessEmail,
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
			TransactItems: []types.TransactWriteItem{
				{
					Update: &types.Update{
						Key:                       userIdKey,
						TableName:                 userTable,
						UpdateExpression:          updateExpression.Update(),
						ExpressionAttributeNames:  updateExpression.Names(),
						ExpressionAttributeValues: updateExpression.Values(),
					},
				},
				{
					Delete: &types.Delete{
						TableName: userUniquenessTable,
						Key: map[string]types.AttributeValue{
							"unique": &types.AttributeValueMemberS{
								Value: userInDatabase.Email,
							},
						},
					},
				},
				{
					Put: &types.Put{
						Item:      emailUniquenessItem,
						TableName: userUniquenessTable,
					},
				},
			},
		})
		if err != nil {
			var emailAlreadyExist *types.ConditionalCheckFailedException
			ok := errors.As(err, &emailAlreadyExist)
			if ok {
				return &cerror.CustomError{
					HttpStatusCode: http.StatusConflict,
					LogMessage:     "email address already exist in user table",
					LogSeverity:    zapcore.WarnLevel,
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
			ReturnValues:              types.ReturnValueNone,
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

func (r *repository) buildUpdateExpression(updateUserPayload *UpdateUserPayload) (expression.Expression, error) {
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
