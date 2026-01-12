FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /app/server ./cmd/server

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/server /app/server
EXPOSE 8443
CMD ["/app/server"]