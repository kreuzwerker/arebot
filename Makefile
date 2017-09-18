REGION ?= eu-central-1
VERSION := 1.0.0
FLAGS := "-X=main.build=`git rev-parse --short HEAD` -X=main.version=$(VERSION)"
NAME := arebot

clean:
	rm -f dist/$(NAME)*

dependencies:
	glide install

dist/$(NAME).exe:
	cd main && CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -a -installsuffix cgo -ldflags $(FLAGS) -o dist/$(NAME).exe

dist/$(NAME)-osx:
	cd main && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -installsuffix cgo -ldflags $(FLAGS) -o ../dist/$(NAME)-osx

dist/$(NAME)-linux:
	cd main && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -installsuffix cgo -ldflags $(FLAGS) -o dist/$(NAME)-linux

build-all: dist/$(NAME).exe dist/$(NAME)-osx dist/$(NAME)-linux
build: dist/$(NAME)-osx

run:
	AWS_REGION=${REGION} ./dist/arebot-osx -config arebot.cfg -loglevel 5
	#AWS_REGION=${REGION} ./dist/arebot-osx -config test/test_create_sg.cfg -loglevel 5
	#AWS_REGION=${REGION} ./dist/arebot-osx -config wall-e.cfg

.PHONY: build clean test


test:
	go test $(go list ./... | grep -v /vendor/)