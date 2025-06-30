package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// GenerateRequestID generates a new random request ID
func GenerateRequestID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple ID if random generation fails
		return "req-fallback"
	}
	return "req-" + hex.EncodeToString(bytes)
}