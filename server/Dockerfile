FROM golang:latest
WORKDIR /appp

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ENV PORT 9090
RUN cd /appp
RUN go run server.go

