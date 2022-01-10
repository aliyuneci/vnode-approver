PROJECT_NAME := vnode-approver
all: build

build:
	env GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build -o bin/${PROJECT_NAME} ./cmd

clean:
	rm -f ./bin/${PROJECT_NAME}