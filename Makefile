.PHONY: build ui test e2e demo clean

build: ui
	go build -o bin/cloudgraph ./cmd/cloudgraph

ui:
	npm --prefix web ci
	npm --prefix web run build

test:
	go vet ./...
	go test ./...

e2e: ui
	npm --prefix web run test:e2e

demo: build
	./bin/cloudgraph serve

clean:
	rm -rf bin web/node_modules web/test-results
	rm -rf internal/ui/dist/app
