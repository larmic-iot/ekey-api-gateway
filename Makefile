.PHONY: build run docker-build docker-run clean

build:
	go build -o gateway ./cmd/gateway

run:
	go run ./cmd/gateway

clean:
	rm -f gateway
