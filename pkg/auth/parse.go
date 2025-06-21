package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/oj-lab/user-service/internal/utils"
	"github.com/oj-lab/user-service/pkg/userpb"
)

type UserInfo struct {
	UserID uint64
	Role   userpb.UserRole
}

func ParseUserToken(tokenString, secret string) (*UserInfo, error) {
	claims, err := utils.ValidateUserToken(tokenString, secret)
	if err != nil {
		return nil, err
	}

	userID, ok := claims.MapClaims["user_id"].(float64)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	role, ok := claims.MapClaims["user_role"].(float64)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return &UserInfo{
		UserID: uint64(userID),
		Role:   userpb.UserRole(role),
	}, nil
}
