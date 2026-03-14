# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/issuer  ./issuer/
RUN CGO_ENABLED=0 go build -o /out/verifier ./verifier/

FROM alpine:3.19 AS issuer
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/issuer /issuer
EXPOSE 8081
ENTRYPOINT ["/issuer"]

FROM alpine:3.19 AS verifier
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /out/verifier /verifier
EXPOSE 8082
ENTRYPOINT ["/verifier"]
