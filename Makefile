PROJECT_NAME = $(notdir $(CURDIR))

get:
	go get ./...
	go mod tidy

security-analysis:
	gosec ./...

lint:
	golangci-lint run -v -c .golangci.yml ./...

dev:
	air .

run:
	go run .

test:
	go clean -testcache
	go test -tags=unit ./...

coverage-report:
	go clean -testcache
	go test -tags=unit -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out

generate-mock:
	mockgen --source=internal/repository.go --destination=internal/repository_mock.go --package=user
	mockgen --source=internal/service.go --destination=internal/service_mock.go --package=user
	mockgen --source=pkg/jwt_generator/jwt.go --destination=pkg/jwt_generator/jwt_mock.go --package=jwt_generator
