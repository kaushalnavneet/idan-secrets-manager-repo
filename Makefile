GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/public-cert cmd/plugin/main.go

localbuild:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/public-cert local/cmd/plugin/main.go

test:
	@CGO_ENABLED=0 go test $(TEST_ARGS) ./

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=acme vault-acme

clean:
	rm -f ./vault/plugins/vault-acme

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
