FROM golang:1.24 AS builder

# Set working directory
WORKDIR /app

COPY . .
RUN make build

# Use a minimal base image for the final stage
FROM ubuntu:latest

# Install ca-certificates for HTTPS requests
RUN apt-get update && apt-get install -y ca-certificates

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/bin/user-service .
# Copy the configs from builder stage
COPY --from=builder /app/configs ./configs

EXPOSE 50051
CMD ["./user-service"]

