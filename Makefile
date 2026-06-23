.PHONY: build run test coverage lint docker-up docker-down

build:
    go build -o coordinator .

run:
    go run .

test:
    go test ./... -v

coverage:
    go test ./... -coverprofile=coverage.out
    go tool cover -func coverage.out

lint:
    go vet ./...

docker-up:
    docker-compose up -d

docker-down:
    docker-compose down

docker-build:
    docker-compose up -d --build
