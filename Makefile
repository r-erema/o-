GOLANG_IMAGE=golang:1.16.3-alpine
GOLANG_CI_LINT_IMAGE=golangci/golangci-lint:latest-alpine
GOOS=darwin

.PHONY: install
install: build-cli
	cp o /usr/local/bin

.PHONY: build-lambda
build-lambda:
	docker run \
		--rm \
		-e GOOS=linux \
		-e CGO_ENABLED=0 \
		-v ${PWD}:/app \
		-w /app \
		$(GOLANG_IMAGE) go build -ldflags="-s -w" -o lambda cmd/lambda/lambda.go
	zip lambda.zip lambda

.PHONY: build-cli
build-cli:
	docker run \
		--rm \
		-e GOOS=${GOOS} \
		-e CGO_ENABLED=0 \
		-e GOARCH=amd64 \
		-v ${PWD}:/app \
		-w /app \
		$(GOLANG_IMAGE) go build -ldflags="-s -w" -o o cmd/cli/cli.go

.PHONY: go-lint
go-lint:
	docker run --rm -v ${PWD}:/app -w /app $(GOLANG_CI_LINT_IMAGE) golangci-lint run --fix --timeout 20m --sort-results

.PHONY: go-test
go-test:
	docker run \
		-v ${PWD}:/app \
		-w /app $(GOLANG_IMAGE) \
		go test -race ./...

.PHONY: keypair
keypair:
	openssl genrsa -out keypair.pem 2048
	openssl rsa -in keypair.pem -pubout -out publickey.crt
	openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key

