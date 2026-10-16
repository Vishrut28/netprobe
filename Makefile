BIN := bin/netprobe

.PHONY: build test lint run clean docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o $(BIN) ./cmd/netprobe

test:
	go test -race -count=1 ./...

lint:
	gofmt -l . | (! grep .) && go vet ./...

run: build
	./$(BIN) check -config targets.example.json

clean:
	rm -rf bin

docker:
	docker build -t netprobe:latest .
