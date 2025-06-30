package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oj-lab/user-service/configs"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OAuthStateData struct {
	Provider  string    `json:"provider"`
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OAuthService interface {
	GenerateState(ctx context.Context, provider, userAgent, ipAddress string) (string, error)
	ValidateState(ctx context.Context, state, userAgent, ipAddress string) (*OAuthStateData, error)
	DeleteState(ctx context.Context, state string) error
}

type oauthService struct {
	rdb    redis.UniversalClient
	config configs.OAuthConfig
}

func NewOAuthService(rdb redis.UniversalClient, config configs.OAuthConfig) OAuthService {
	return &oauthService{
		rdb:    rdb,
		config: config,
	}
}

// GenerateState generates a new OAuth state
func (s *oauthService) GenerateState(
	ctx context.Context,
	provider, userAgent, ipAddress string,
) (string, error) {
	// Generate random state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate state: %v", err)
	}
	state := hex.EncodeToString(stateBytes)

	// Create state data
	now := time.Now()
	stateTTL := time.Duration(s.config.StateExpirationMinutes) * time.Minute
	stateData := OAuthStateData{
		Provider:  provider,
		UserAgent: userAgent,
		IPAddress: ipAddress,
		CreatedAt: now,
		ExpiresAt: now.Add(stateTTL),
	}

	// Store state data in Redis
	dataBytes, err := json.Marshal(stateData)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to marshal state data: %v", err)
	}

	stateKey := fmt.Sprintf("oauth_state:%s", state)
	err = s.rdb.Set(ctx, stateKey, string(dataBytes), stateTTL).Err()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to store state: %v", err)
	}

	return state, nil
}

// ValidateState validates OAuth state and returns state data
func (s *oauthService) ValidateState(
	ctx context.Context,
	state, userAgent, ipAddress string,
) (*OAuthStateData, error) {
	stateKey := fmt.Sprintf("oauth_state:%s", state)
	dataStr, err := s.rdb.Get(ctx, stateKey).Result()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid or expired state")
	}

	var stateData OAuthStateData
	if err := json.Unmarshal([]byte(dataStr), &stateData); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal state data: %v", err)
	}

	// Validate expiration
	if time.Now().After(stateData.ExpiresAt) {
		// Clean up expired state
		s.DeleteState(ctx, state)
		return nil, status.Errorf(codes.InvalidArgument, "state has expired")
	}

	// Validate user agent if provided during creation (optional but recommended)
	if stateData.UserAgent != "" && userAgent != "" && stateData.UserAgent != userAgent {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"user agent mismatch - possible session hijacking",
		)
	}

	// Validate IP address if provided during creation (optional but recommended)
	if stateData.IPAddress != "" && ipAddress != "" && stateData.IPAddress != ipAddress {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"IP address mismatch - possible session hijacking",
		)
	}

	return &stateData, nil
}

// DeleteState removes OAuth state from Redis
func (s *oauthService) DeleteState(ctx context.Context, state string) error {
	stateKey := fmt.Sprintf("oauth_state:%s", state)
	return s.rdb.Del(ctx, stateKey).Err()
}
