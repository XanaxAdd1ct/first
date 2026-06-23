FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o coordinator .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/coordinator .
EXPOSE 8080
ENTRYPOINT ["./coordinator"]
