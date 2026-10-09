FROM --platform=$BUILDPLATFORM golang:1.27.2 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.4.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w -X github.com/RamazanKara/fencepost/internal/version.Version=${VERSION}" -o /fencepost ./cmd/fencepost
RUN mkdir /data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build --chmod=0555 /fencepost /fencepost
COPY --from=build --chown=65532:65532 /data /data
WORKDIR /data
ENTRYPOINT ["/fencepost"]
CMD ["--help"]
