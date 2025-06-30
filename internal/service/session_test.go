package service

import (
	"context"
	"testing"
	"time"

	"github.com/oj-lab/user-service/configs"
	"github.com/redis/go-redis/v9"
)

func TestSessionRefresh(t *testing.T) {
	// Use in-memory Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use a different DB for testing
	})
	
	// Skip test if Redis is not available
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	sessionService := NewSessionService(rdb, configs.SessionConfig{
		ExpirationHours: 24,
	})
	userID := uint(123)

	// Create a session
	sessionID, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Get initial TTL
	sessionKey := "session:" + sessionID
	initialTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get initial TTL: %v", err)
	}

	// Wait a bit to let some time pass
	time.Sleep(100 * time.Millisecond)

	// Refresh the session
	err = sessionService.RefreshSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to refresh session: %v", err)
	}

	// Get TTL after refresh
	refreshedTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get refreshed TTL: %v", err)
	}

	// The refreshed TTL should be approximately 24 hours and greater than initial TTL
	expectedTTL := 24 * time.Hour
	if refreshedTTL < expectedTTL-time.Minute || refreshedTTL > expectedTTL {
		t.Errorf("Expected TTL around %v, got %v", expectedTTL, refreshedTTL)
	}

	if refreshedTTL <= initialTTL {
		t.Errorf("Expected refreshed TTL (%v) to be greater than initial TTL (%v)", refreshedTTL, initialTTL)
	}

	// Verify we can still get the user ID
	retrievedUserID, err := sessionService.GetUserIDFromSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get user ID from session: %v", err)
	}

	if retrievedUserID != userID {
		t.Errorf("Expected user ID %d, got %d", userID, retrievedUserID)
	}

	// Get session expiration time
	expiresAt, err := sessionService.GetSessionExpirationTime(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get session expiration time: %v", err)
	}

	// The expiration time should be approximately 24 hours from now
	expectedExpiration := time.Now().Add(24 * time.Hour)
	if expiresAt.Before(expectedExpiration.Add(-time.Minute)) || expiresAt.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected expiration around %v, got %v", expectedExpiration, expiresAt)
	}

	// Clean up
	err = sessionService.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}
}

func TestGetUserIDFromSessionRefreshesSession(t *testing.T) {
	// Use in-memory Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use a different DB for testing
	})
	
	// Skip test if Redis is not available
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	sessionService := NewSessionService(rdb, configs.SessionConfig{
		ExpirationHours: 24,
	})
	userID := uint(456)

	// Create a session
	sessionID, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Get initial TTL
	sessionKey := "session:" + sessionID
	initialTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get initial TTL: %v", err)
	}

	// Wait a bit to let some time pass
	time.Sleep(100 * time.Millisecond)

	// Get user ID from session (this should refresh the session)
	retrievedUserID, err := sessionService.GetUserIDFromSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get user ID from session: %v", err)
	}

	if retrievedUserID != userID {
		t.Errorf("Expected user ID %d, got %d", userID, retrievedUserID)
	}

	// Get TTL after GetUserIDFromSession call
	refreshedTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get refreshed TTL: %v", err)
	}

	// The refreshed TTL should be greater than initial TTL due to automatic refresh
	if refreshedTTL <= initialTTL {
		t.Errorf("Expected GetUserIDFromSession to refresh session: refreshed TTL (%v) should be greater than initial TTL (%v)", refreshedTTL, initialTTL)
	}

	// Clean up
	err = sessionService.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}
}