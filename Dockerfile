# Build stage
FROM golang:1.22 AS builder

WORKDIR /app

COPY main.go .
COPY go.mod .

# Statically compile the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server

# Final stage: distroless
FROM gcr.io/distroless/static-debian12

WORKDIR /

# Copy the statically compiled Go binary
COPY --from=builder /app/server /

# Expose port (for documentation only)
EXPOSE 8080

# Run the binary (no shell in distroless)
ENTRYPOINT ["/server"]
