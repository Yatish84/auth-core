FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/jwt-verifier ./cmd/server

FROM alpine:3.22
RUN adduser -D -H -u 10001 appuser
USER appuser
COPY --from=build /out/jwt-verifier /usr/local/bin/jwt-verifier
EXPOSE 8081
ENTRYPOINT ["jwt-verifier"]
