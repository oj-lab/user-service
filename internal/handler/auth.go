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
	"github.com/oj-lab/user-service/pkg/logger"
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
	// Generate request ID for tracing
	requestID := logger.GenerateRequestID()
	ctx = logger.WithRequestID(ctx, requestID)
	log := logger.WithContext(ctx)

	log.Info("oauth code url request started", 
		"provider", req.Provider,
		"ip_address", h.extractIPAddress(ctx),
		"user_agent", h.extractUserAgent(ctx))

	if req.Provider == "" {
		log.Warn("oauth code url request failed", "error", "provider is required")
		return nil, status.Errorf(codes.InvalidArgument, "provider is required")
	}
	oauthConfig, exists := h.oauthConfigs[req.Provider]
	if !exists {
		log.Warn("oauth code url request failed", "error", "unsupported provider", "provider", req.Provider)
		return nil, status.Errorf(codes.InvalidArgument, "unsupported provider: %s", req.Provider)
	}

	// Extract client information for additional security
	userAgent := h.extractUserAgent(ctx)
	ipAddress := h.extractIPAddress(ctx)

	// Generate state with embedded CSRF protection
	state, err := h.oauthService.GenerateState(ctx, req.Provider, userAgent, ipAddress)
	if err != nil {
		log.Error("oauth state generation failed", "error", err, "provider", req.Provider)
		return nil, err
	}

	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	log.Info("oauth code url generated successfully", 
		"provider", req.Provider,
		"state_id", state[:16], // Log partial state for debugging
		"ip_address", ipAddress)

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
	// Generate request ID for tracing
	requestID := logger.GenerateRequestID()
	ctx = logger.WithRequestID(ctx, requestID)
	log := logger.WithContext(ctx)

	ipAddress := h.extractIPAddress(ctx)
	userAgent := h.extractUserAgent(ctx)

	log.Info("oauth login attempt started", 
		"ip_address", ipAddress,
		"user_agent", userAgent)

	if req.Code == "" || req.State == "" {
		log.Warn("oauth login failed", "error", "code and state are required", "has_code", req.Code != "", "has_state", req.State != "")
		return nil, status.Errorf(codes.InvalidArgument, "code and state are required")
	}

	stateData, err := h.oauthService.ValidateState(ctx, req.State, userAgent, ipAddress)
	if err != nil {
		log.Warn("oauth state validation failed", "error", err, "state_prefix", req.State[:min(16, len(req.State))], "ip_address", ipAddress)
		return nil, err
	}

	log.Info("oauth state validated successfully", "provider", stateData.Provider)

	// Delete used state
	h.oauthService.DeleteState(ctx, req.State)

	oauthConfig, exists := h.oauthConfigs[stateData.Provider]
	if !exists {
		log.Error("unsupported oauth provider", "provider", stateData.Provider)
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported provider: %s",
			stateData.Provider,
		)
	}

	// Exchange code for token
	token, err := oauthConfig.Exchange(ctx, req.Code)
	if err != nil {
		log.Error("oauth token exchange failed", "error", err, "provider", stateData.Provider)
		return nil, status.Errorf(codes.Internal, "failed to exchange code for token: %v", err)
	}

	log.Debug("oauth token exchange successful", "provider", stateData.Provider)

	// Get user info from provider
	userProvider, err := providerPkg.GetUserProvider(stateData.Provider)
	if err != nil {
		log.Error("failed to get user provider", "error", err, "provider", stateData.Provider)
		return nil, status.Errorf(codes.Internal, "failed to get user provider: %v", err)
	}

	userInfo, err := userProvider.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		log.Error("failed to get user info from provider", "error", err, "provider", stateData.Provider)
		return nil, status.Errorf(codes.Internal, "failed to get user info: %v", err)
	}

	log.Info("user info retrieved from provider", "provider", stateData.Provider, "user_id", userInfo.ID, "email", userInfo.Email)

	// Find or create user
	var user *model.UserModel
	var isNewUser bool
	if stateData.Provider == "github" {
		user, err = h.userRepo.GetByGithubID(ctx, userInfo.ID)
		if err != nil && err != gorm.ErrRecordNotFound {
			log.Error("failed to query user by github id", "error", err, "github_id", userInfo.ID)
			return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
		}

		if user == nil {
			isNewUser = true
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
				log.Error("failed to create new user", "error", err, "email", userInfo.Email, "github_id", userInfo.ID)
				return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
			}
			log.Info("new user created successfully", "user_id", user.ID, "email", user.Email, "provider", stateData.Provider)
		} else {
			// Update last login
			now := time.Now()
			user.LastLoginAt = &now
			if err := h.userRepo.Update(ctx, user); err != nil {
				log.Error("failed to update user last login", "error", err, "user_id", user.ID)
				return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
			}
			log.Info("existing user login successful", "user_id", user.ID, "email", user.Email, "provider", stateData.Provider)
		}
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		log.Error("failed to create login session", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	log.Info("oauth login completed successfully", 
		"user_id", user.ID, 
		"session_id", sessionID[:16], 
		"provider", stateData.Provider,
		"is_new_user", isNewUser,
		"ip_address", ipAddress)

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
	// Generate request ID for tracing
	requestID := logger.GenerateRequestID()
	ctx = logger.WithRequestID(ctx, requestID)
	log := logger.WithContext(ctx)

	ipAddress := h.extractIPAddress(ctx)
	userAgent := h.extractUserAgent(ctx)

	log.Info("password login attempt started", 
		"email", req.Email,
		"ip_address", ipAddress,
		"user_agent", userAgent)

	if req.Email == "" || req.Password == "" {
		log.Warn("password login failed", "error", "email and password are required", "has_email", req.Email != "", "has_password", req.Password != "")
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	// Get user by email
	user, err := h.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			log.Warn("password login failed", "error", "user not found", "email", req.Email, "ip_address", ipAddress)
			return nil, status.Errorf(codes.NotFound, "invalid credentials")
		}
		log.Error("failed to query user for password login", "error", err, "email", req.Email)
		return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
	}

	// Check if user has a password set
	if user.HashedPassword == nil {
		log.Warn("password login attempt for oauth-only account", "user_id", user.ID, "email", req.Email, "ip_address", ipAddress)
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"password login not available for this account",
		)
	}

	// Verify password
	valid, err := utils.VerifyPassword(req.Password, *user.HashedPassword)
	if err != nil {
		log.Error("password verification error", "error", err, "user_id", user.ID, "email", req.Email)
		return nil, status.Errorf(codes.Internal, "failed to verify password: %v", err)
	}
	if !valid {
		log.Warn("password login failed", "error", "invalid password", "user_id", user.ID, "email", req.Email, "ip_address", ipAddress)
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := h.userRepo.Update(ctx, user); err != nil {
		log.Error("failed to update user last login", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		log.Error("failed to create login session", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	log.Info("password login completed successfully", 
		"user_id", user.ID, 
		"email", req.Email,
		"session_id", sessionID[:16],
		"ip_address", ipAddress)

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
	// Generate request ID for tracing
	requestID := logger.GenerateRequestID()
	ctx = logger.WithRequestID(ctx, requestID)
	log := logger.WithContext(ctx)

	log.Info("user token request started", "session_id", req.SessionId[:min(16, len(req.SessionId))])

	if req.SessionId == "" {
		log.Warn("user token request failed", "error", "session_id is required")
		return nil, status.Errorf(codes.InvalidArgument, "session_id is required")
	}

	// Get user ID from session (this automatically refreshes the session)
	userID, err := h.sessionService.GetUserIDFromSession(ctx, req.SessionId)
	if err != nil {
		log.Warn("user token request failed", "error", "invalid or expired session", "session_id", req.SessionId[:min(16, len(req.SessionId))])
		return nil, err
	}

	// Get session expiration time after refresh
	sessionExpiresAt, err := h.sessionService.GetSessionExpirationTime(ctx, req.SessionId)
	if err != nil {
		log.Error("failed to get session expiration time", "error", err, "user_id", userID, "session_id", req.SessionId[:min(16, len(req.SessionId))])
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}

	// Get user details
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		log.Error("failed to get user details for token generation", "error", err, "user_id", userID)
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Generate JWT token with session expiration time
	// This ensures the token expires when the session expires
	userToken, err := utils.NewUserTokenWithExpiration(uint64(user.ID), user.Role, h.config.Auth.JWTSecret, sessionExpiresAt)
	if err != nil {
		log.Error("failed to generate JWT token", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	log.Info("user token generated successfully", 
		"user_id", user.ID, 
		"role", user.Role, 
		"session_id", req.SessionId[:16],
		"token_expires_at", sessionExpiresAt)

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
