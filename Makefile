-include .env
export

.PHONY: build run clean docker-build docker-run docker-up docker-down

build:
	go build -o gateway ./cmd/gateway

run:
	go run ./cmd/gateway

clean:
	rm -f gateway

docker-build:
	docker build -t ekey-api-gateway .

docker-run: docker-build
	docker run --rm -p 8080:8080 \
		-e EKEY_EMAIL="$(EKEY_EMAIL)" \
		-e EKEY_PASSWORD="$(EKEY_PASSWORD)" \
		ekey-api-gateway

docker-up:
	docker compose up --build
