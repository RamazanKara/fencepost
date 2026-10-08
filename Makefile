.PHONY: lint test e2e build

lint:
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run

test:
	go test -race ./...

e2e:
	go test -race -tags=e2e ./cmd/fencepost ./internal/report ./internal/policy

build:
	go run scripts/build.go
