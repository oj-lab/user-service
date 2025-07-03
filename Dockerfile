FROM golang:1.24 AS builder

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Copy vendor directory
COPY vendor/ ./vendor/

# Copy source code
COPY . .

# Build the application using vendor modules
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -a -installsuffix cgo -o bin/user-service cmd/main.go

# Final stage
FROM alpine:latest

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory to appuser's home
WORKDIR /home/appuser

# Copy the binary from builder stage
COPY --from=builder /app/bin/user-service .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Change ownership to appuser
RUN chown -R appuser:appuser /home/appuser
USER appuser

# Expose port
EXPOSE 50051

# Command to run
CMD ["./user-service"]

