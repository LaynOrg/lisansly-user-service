package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/kr/pretty"
)

type Config struct {
	ServerPort string
	Mongodb    MongodbConfig
	Jwt        JwtConfig
}

func ReadConfig() (*Config, error) {
	serverPort := os.Getenv(ServerPort)
	if serverPort == "" {
		serverPort = "8080"
		fmt.Println("server port environment variable is empty its declared 8080 by default")
	}

	mongodbConfig, err := ReadMongoDbConfig()
	if err != nil {
		return nil, err
	}

	jwtConfig, err := ReadJwtConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		ServerPort: serverPort,
		Mongodb:    mongodbConfig,
		Jwt:        jwtConfig,
	}, nil
}

func (c *Config) Print() {
	_, _ = pretty.Println(c)
}

func ReadMongoDbConfig() (MongodbConfig, error) {
	mongodbUri := os.Getenv(MongodbUri)
	if mongodbUri == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongodbUri)
	}

	mongodbUsername := os.Getenv(MongodbUsername)
	if mongodbUsername == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongodbUsername)
	}

	mongodbPassword := os.Getenv(MongodbPassword)
	if mongodbUsername == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongodbPassword)
	}

	mongodbDatabase := os.Getenv(MongodbDatabase)
	if mongodbDatabase == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongodbDatabase)
	}

	mongodbUserCollection := os.Getenv(MongodbUserCollection)
	if mongodbUserCollection == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongodbUserCollection)
	}

	mongoDbRefreshTokenHistoryCollection := os.Getenv(MongoDbRefreshTokenHistoryCollection)
	if mongodbUserCollection == "" {
		return MongodbConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, MongoDbRefreshTokenHistoryCollection)
	}

	return MongodbConfig{
		Uri:      mongodbUri,
		Username: mongodbUsername,
		Password: mongodbPassword,
		Database: mongodbDatabase,
		Collections: map[string]string{
			MongodbUserCollection:                mongodbUserCollection,
			MongoDbRefreshTokenHistoryCollection: mongoDbRefreshTokenHistoryCollection,
		},
	}, nil
}

func ReadJwtConfig() (JwtConfig, error) {
	privateKey := os.Getenv(JwtPrivateKey)
	if privateKey == "" {
		return JwtConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey)
	}
	privateKey = strings.ReplaceAll(privateKey, `\n`, "\n")

	publicKey := os.Getenv(JwtPublicKey)
	if publicKey == "" {
		return JwtConfig{}, fmt.Errorf(EnvironmentVariableNotDefined, JwtPublicKey)
	}
	publicKey = strings.ReplaceAll(publicKey, `\n`, "\n")

	return JwtConfig{
		PrivateKey: []byte(privateKey),
		PublicKey:  []byte(publicKey),
	}, nil
}
