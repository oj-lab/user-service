package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID uint) (string, error)
	GetUserIDFromSession(ctx context.Context, sessionID string) (uint, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

type sessionService struct {
	rdb redis.UniversalClient
}

func NewSessionService(rdb redis.UniversalClient) SessionService {
	return &sessionService{
		rdb: rdb,
	}
}

// CreateSession creates a new login session and stores it in Redis
func (s *sessionService) CreateSession(ctx context.Context, userID uint) (string, error) {
	// Generate session ID
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate session ID: %v", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	// Store session in Redis with 24 hour expiration
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	err := s.rdb.Set(ctx, sessionKey, fmt.Sprintf("%d", userID), 24*time.Hour).Err()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to store session: %v", err)
	}

	return sessionID, nil
}

// GetUserIDFromSession retrieves user ID from session
func (s *sessionService) GetUserIDFromSession(ctx context.Context, sessionID string) (uint, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	userIDStr, err := s.rdb.Get(ctx, sessionKey).Result()
	if err != nil {
		return 0, status.Errorf(codes.Unauthenticated, "invalid or expired session")
	}

	var userID uint
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		return 0, status.Errorf(codes.Internal, "invalid session data")
	}

	return userID, nil
}

// DeleteSession removes session from Redis
func (s *sessionService) DeleteSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	return s.rdb.Del(ctx, sessionKey).Err()
}
