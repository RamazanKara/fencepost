FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /upstream ./examples/gateway/upstream
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /upstream /upstream
ENTRYPOINT ["/upstream"]
