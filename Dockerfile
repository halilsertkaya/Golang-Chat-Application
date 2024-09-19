FROM golang:1.23 as builder

WORKDIR /chatapp

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

FROM debian:bookworm

WORKDIR /chatapp

COPY --from=builder /chatapp/main .

# Required Lib/Frameworks.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Run the application.
CMD ["./main"]
# Open the default customized port 9999
EXPOSE 9999