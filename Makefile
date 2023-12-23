get:
	go get ./...
	go mod tidy

.PHONY: build
build:
	env GOOS=linux GOARCH=arm64 go build -o build/register/bootstrap internal/register/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/login/bootstrap internal/login/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/getUserById/bootstrap internal/getUserById/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/getAccessTokenByRefreshToken/bootstrap internal/getAccessTokenByRefreshToken/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/updateUserById/bootstrap internal/updateUserById/main.go

.PHONY: zip
zip:
	zip -j build/register/register.zip build/register/bootstrap
	zip -j build/login/login.zip build/login/bootstrap
	zip -j build/getUserById/getUserById.zip build/getUserById/bootstrap
	zip -j build/getAccessTokenByRefreshToken/getAccessTokenByRefreshToken.zip build/getAccessTokenByRefreshToken/bootstrap
	zip -j build/updateUserById/updateUserById.zip build/updateUserById/bootstrap

security-analysis:
	gosec -tests ./...

lint:
	golangci-lint run -v -c .golangci.yml ./...

test:
	go clean -testcache
	go test -tags=unit ./...

coverage-report:
	go clean -testcache
	go test -tags=unit -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o=coverage.html

generate-mock:
	mockgen --source=internal/repository.go --destination=internal/repository_mock.go --package=user
	mockgen --source=internal/service.go --destination=internal/service_mock.go --package=user
	mockgen --source=pkg/jwt_generator/jwt.go --destination=pkg/jwt_generator/jwt_mock.go --package=jwt_generator
