package context

import (
	"context"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	// Check that IDs are not empty
	if id1 == "" || id2 == "" {
		t.Error("GenerateRequestID should not return empty string")
	}

	// Check that IDs are unique
	if id1 == id2 {
		t.Error("GenerateRequestID should generate unique IDs")
	}

	// Check that IDs have the correct prefix
	if len(id1) < 4 || id1[:4] != "req-" {
		t.Errorf("GenerateRequestID should start with 'req-', got: %s", id1)
	}
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-id"

	// Add request ID to context
	ctxWithID := WithRequestID(ctx, requestID)

	// Retrieve request ID from context
	retrievedID := GetRequestID(ctxWithID)

	if retrievedID != requestID {
		t.Errorf("Expected %s, got %s", requestID, retrievedID)
	}
}

func TestGetRequestIDFromEmptyContext(t *testing.T) {
	ctx := context.Background()
	retrievedID := GetRequestID(ctx)

	if retrievedID != "" {
		t.Errorf("Expected empty string from context without request ID, got %s", retrievedID)
	}
}