FROM golang:latest
WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ENV PORT 8081
RUN cd /app
RUN go run client.go

