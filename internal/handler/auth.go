package handler

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/oj-lab/user-service/configs"
	"github.com/oj-lab/user-service/internal/model"
	providerPkg "github.com/oj-lab/user-service/internal/provider"
	"github.com/oj-lab/user-service/internal/repository"
	"github.com/oj-lab/user-service/internal/service"
	"github.com/oj-lab/user-service/internal/utils"
	"github.com/oj-lab/user-service/pkg/userpb"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db             *gorm.DB
	userRepo       repository.UserRepository
	oauthService   service.OAuthService
	sessionService service.SessionService
	config         configs.Config
	oauthConfigs   map[string]*oauth2.Config
	userpb.UnimplementedAuthServiceServer
}

func NewAuthHandler(db *gorm.DB, rdb redis.UniversalClient) *AuthHandler {
	config := configs.Load()

	// Initialize OAuth configurations
	oauthConfigs := make(map[string]*oauth2.Config)
	oauthConfigs["github"] = &oauth2.Config{
		ClientID:     config.Auth.GithubClientID,
		ClientSecret: config.Auth.GithubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
		RedirectURL:  config.Auth.GithubRedirectURL,
	}

	return &AuthHandler{
		db:             db,
		userRepo:       repository.NewUserRepository(db),
		oauthService:   service.NewOAuthService(rdb),
		sessionService: service.NewSessionService(rdb),
		config:         config,
		oauthConfigs:   oauthConfigs,
	}
}

// GetOAuthCodeURL generates OAuth authorization URL with embedded CSRF protection
func (h *AuthHandler) GetOAuthCodeURL(
	ctx context.Context,
	req *userpb.GetOAuthCodeURLRequest,
) (*userpb.GetOAuthCodeURLResponse, error) {
	if req.Provider == "" {
		return nil, status.Errorf(codes.InvalidArgument, "provider is required")
	}
	oauthConfig, exists := h.oauthConfigs[req.Provider]
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported provider: %s", req.Provider)
	}

	// Extract client information for additional security
	userAgent := h.extractUserAgent(ctx)
	ipAddress := h.extractIPAddress(ctx)

	// Generate state with embedded CSRF protection
	state, err := h.oauthService.GenerateState(ctx, req.Provider, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}

	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	return &userpb.GetOAuthCodeURLResponse{
		Url:   url,
		State: state, // Return the state containing all security information
	}, nil
}

// LoginByOAuth handles OAuth login flow with CSRF protection
func (h *AuthHandler) LoginByOAuth(
	ctx context.Context,
	req *userpb.LoginByOAuthRequest,
) (*userpb.LoginSession, error) {
	if req.Code == "" || req.State == "" {
		return nil, status.Errorf(codes.InvalidArgument, "code and state are required")
	}

	// Extract client information for validation
	userAgent := h.extractUserAgent(ctx)
	ipAddress := h.extractIPAddress(ctx)

	stateData, err := h.oauthService.ValidateState(ctx, req.State, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}

	// Delete used state
	h.oauthService.DeleteState(ctx, req.State)

	oauthConfig, exists := h.oauthConfigs[stateData.Provider]
	if !exists {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported provider: %s",
			stateData.Provider,
		)
	}

	// Exchange code for token
	token, err := oauthConfig.Exchange(ctx, req.Code)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to exchange code for token: %v", err)
	}

	// Get user info from provider
	userProvider, err := providerPkg.GetUserProvider(stateData.Provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user provider: %v", err)
	}

	userInfo, err := userProvider.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user info: %v", err)
	}

	// Find or create user
	var user *model.UserModel
	if stateData.Provider == "github" {
		user, err = h.userRepo.GetByGithubID(ctx, userInfo.ID)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
		}

		if user == nil {
			// Create new user
			now := time.Now()
			user = &model.UserModel{
				Name:        userInfo.Name,
				Email:       userInfo.Email,
				GithubID:    &userInfo.ID,
				LastLoginAt: &now,
				Role:        model.UserRoleUser,
			}

			if err := h.userRepo.Create(ctx, user); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
			}
		} else {
			// Update last login
			now := time.Now()
			user.LastLoginAt = &now
			if err := h.userRepo.Update(ctx, user); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
			}
		}
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	return &userpb.LoginSession{
		Id:        sessionID,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// LoginByPassword handles password-based login
func (h *AuthHandler) LoginByPassword(
	ctx context.Context,
	req *userpb.LoginByPasswordRequest,
) (*userpb.LoginSession, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	// Get user by email
	user, err := h.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, status.Errorf(codes.NotFound, "invalid credentials")
		}
		return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
	}

	// Check if user has a password set
	if user.HashedPassword == nil {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"password login not available for this account",
		)
	}

	// Verify password
	valid, err := utils.VerifyPassword(req.Password, *user.HashedPassword)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify password: %v", err)
	}
	if !valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := h.userRepo.Update(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	return &userpb.LoginSession{
		Id:        sessionID,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// GetUserToken generates JWT token for authenticated users
func (h *AuthHandler) GetUserToken(
	ctx context.Context,
	req *userpb.GetUserTokenRequest,
) (*userpb.UserToken, error) {
	if req.SessionId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "session_id is required")
	}

	// Get user ID from session (this automatically refreshes the session)
	userID, err := h.sessionService.GetUserIDFromSession(ctx, req.SessionId)
	if err != nil {
		return nil, err
	}

	// Get session expiration time after refresh
	sessionExpiresAt, err := h.sessionService.GetSessionExpirationTime(ctx, req.SessionId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}

	// Get user details
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Generate JWT token with session expiration time
	// This ensures the token expires when the session expires
	userToken, err := utils.NewUserTokenWithExpiration(uint64(user.ID), user.Role, h.config.Auth.JWTSecret, sessionExpiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return userToken, nil
}

// extractUserAgent extracts user agent from gRPC metadata
func (h *AuthHandler) extractUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		userAgents := md.Get("user-agent")
		if len(userAgents) > 0 {
			return userAgents[0]
		}
	}
	return ""
}

// extractIPAddress extracts IP address from gRPC peer info
func (h *AuthHandler) extractIPAddress(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if addr := p.Addr; addr != nil {
			// Handle different address types
			switch addr := addr.(type) {
			case *net.TCPAddr:
				return addr.IP.String()
			case *net.UDPAddr:
				return addr.IP.String()
			default:
				// Try to parse the string representation
				addrStr := addr.String()
				if host, _, err := net.SplitHostPort(addrStr); err == nil {
					return host
				}
				// Check for X-Forwarded-For header in metadata
				if md, ok := metadata.FromIncomingContext(ctx); ok {
					xForwardedFor := md.Get("x-forwarded-for")
					if len(xForwardedFor) > 0 {
						// Get the first IP from the comma-separated list
						ips := strings.Split(xForwardedFor[0], ",")
						if len(ips) > 0 {
							return strings.TrimSpace(ips[0])
						}
					}

					xRealIP := md.Get("x-real-ip")
					if len(xRealIP) > 0 {
						return xRealIP[0]
					}
				}
				return addrStr
			}
		}
	}
	return ""
}
