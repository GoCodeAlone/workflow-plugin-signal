VERSION ?= 0.8.0

.PHONY: build test install-local generate-contracts clean

build:
	go build -ldflags "-X github.com/GoCodeAlone/workflow-plugin-signal/internal.Version=$(VERSION)" -o workflow-plugin-signal ./cmd/workflow-plugin-signal

test:
	go test ./...

generate-contracts:
	protoc --go_out=. --go_opt=paths=source_relative internal/contracts/signal.proto

install-local: build
	wfctl plugin install --local .

clean:
	rm -f workflow-plugin-signal
