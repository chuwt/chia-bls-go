test:
	go test -v ./...

lint-deps:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.45.2

lint:
	./bin/golangci-lint run
