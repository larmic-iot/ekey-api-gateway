FROM golang:1.26.1-alpine AS builder

RUN apk add --no-cache ca-certificates

WORKDIR /go/src/app/
COPY . /go/src/app/

RUN go mod download
RUN CGO_ENABLED=0 go build -a -o main ./cmd/gateway

FROM scratch

LABEL org.opencontainers.image.source="https://github.com/larmic-iot/ekey-api-gateway"
LABEL org.opencontainers.image.description="ekey bionyx API Gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /root/

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/app/main .

EXPOSE 8080
ENTRYPOINT ["./main"]
