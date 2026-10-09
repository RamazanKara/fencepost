.PHONY: lint test e2e build release image docs ui-test

lint:
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run

test:
	go test -race ./...

e2e:
	go test -race -tags=e2e ./cmd/fencepost ./internal/report ./internal/policy
	go test -tags=e2e ./deploy/helm

build:
	go run scripts/build.go

release:
	go run scripts/build.go release

image:
	docker build -t fencepost:0.3.0 .

docs:
	go run scripts/docs.go

ui-test:
	go run scripts/ui-fixture.go
	npm run test:ui
