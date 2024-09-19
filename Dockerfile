FROM golang:1.23.1

WORKDIR /chatapp

COPY . .

RUN go mod download
RUN go build -o main .


CMD ["./main"]