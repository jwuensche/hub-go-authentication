FROM golang:latest

WORKDIR /go/src/hub-go-auth
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["hub-go-auth"]
