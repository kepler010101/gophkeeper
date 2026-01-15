VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X gophkeeper/internal/version.Version=$(VERSION) -X gophkeeper/internal/version.BuildDate=$(BUILD_DATE)

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

test:
	go test ./... -coverprofile=coverage.out -coverpkg=./...

cover-check:
	go test ./... -coverprofile=coverage.out -coverpkg=./...
	go tool cover -func=coverage.out | awk '/total:/ {gsub("%","",$3); if ($3+0 < 80) {print "coverage too low:" $3 "%"; exit 1} else {print "coverage ok:" $3 "%"}}'

gen-cert:
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

run-server:
	GOPHKEEPER_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= GOPHKEEPER_JWT_SECRET=dev_jwt_secret_32_chars_min_123456 GOPHKEEPER_DB_DSN=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable GOPHKEEPER_TLS_CERT=certs/server.crt GOPHKEEPER_TLS_KEY=certs/server.key go run ./cmd/server

run-client:
	go run ./cmd/client --help
