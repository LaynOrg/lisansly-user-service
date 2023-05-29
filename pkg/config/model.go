package config

// #nosec
const (
	EnvironmentVariableNotDefined = "%s variable is not defined"

	IsAtRemote = "IS_AT_REMOTE"
	ServerPort = "PORT"

	MongodbUri                           = "MONGODB_URI"
	MongodbUsername                      = "MONGODB_USERNAME"
	MongodbPassword                      = "MONGODB_PASSWORD"
	MongodbDatabase                      = "MONGODB_DATABASE"
	MongodbUserCollection                = "MONGODB_USER_COLLECTION"
	MongoDbRefreshTokenHistoryCollection = "MONGODB_REFRESH_TOKEN_HISTORY_COLLECTION"

	JwtPrivateKey = "JWT_PRIVATE_KEY"
	JwtPublicKey  = "JWT_PUBLIC_KEY"
)

type MongodbConfig struct {
	Uri         string
	Username    string
	Password    string
	Database    string
	Collections map[string]string
}

type JwtConfig struct {
	PrivateKey string
	PublicKey  string
}
