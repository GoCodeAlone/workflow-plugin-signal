.PHONY: build test install-local clean

build:
	go build -o workflow-plugin-signal ./cmd/workflow-plugin-signal

test:
	go test ./...

install-local: build
	wfctl plugin install --local .

clean:
	rm -f workflow-plugin-signal
