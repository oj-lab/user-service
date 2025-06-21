package auth

import (
	"context"
	"strings"

	"github.com/oj-lab/go-webmods/app"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	configKeyInternalToken = "auth.internal_token"
)

func BuildAuthInterceptor(
	publicMethodMap map[string]bool,
	jwtSecret string,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if ok := publicMethodMap[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		tokenType := md.Get("x-token-type")
		if len(tokenType) == 0 {
			tokenType = []string{"user"} // Default to user token if not specified
		}
		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		switch tokenType[0] {
		case "internal":
			token := strings.TrimPrefix(authHeader[0], "Bearer ")
			internalToken := app.Config().GetString(configKeyInternalToken)
			if token != internalToken {
				return nil, status.Error(codes.Unauthenticated, "invalid internal token")
			}
		default:
			token := strings.TrimPrefix(authHeader[0], "Bearer ")
			userInfo, err := ParseUserToken(token, jwtSecret)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, "invalid token")
			}
			ctx = context.WithValue(ctx, "user_info", userInfo)
		}
		return handler(ctx, req)
	}
}
