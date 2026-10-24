# syntax=docker/dockerfile:1
FROM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/ui/dist/app ./internal/ui/dist/app
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cloudgraph ./cmd/cloudgraph

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cloudgraph /usr/local/bin/cloudgraph
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["cloudgraph"]
# Inside a container the server must listen on all interfaces; publish it to
# loopback only on the host: docker run -p 127.0.0.1:8080:8080 cloudgraph
CMD ["serve", "--addr", "0.0.0.0:8080", "--db", "/data/cloudgraph.db"]
