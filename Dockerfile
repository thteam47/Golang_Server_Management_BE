FROM golang:latest
WORKDIR /appp1

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ENV PORT 9090
CMD [ "go","run","server/server.go" ]