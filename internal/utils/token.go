package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oj-lab/user-service/internal/model"
	"github.com/oj-lab/user-service/pkg/userpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserTokenClaims struct {
	jwt.MapClaims
}

func NewUserTokenClaims(userID uint64, role model.UserRole) UserTokenClaims {
	return NewUserTokenClaimsWithExpiration(userID, role, time.Now().Add(24*time.Hour))
}

func NewUserTokenClaimsWithExpiration(userID uint64, role model.UserRole, expiresAt time.Time) UserTokenClaims {
	return UserTokenClaims{
		MapClaims: jwt.MapClaims{
			"user_id":   userID,
			"user_role": role.ToPb(),
			"exp":       expiresAt.Unix(),
		},
	}
}

func (c UserTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.MapClaims.GetExpirationTime()
}
func (c UserTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.MapClaims.GetNotBefore()
}
func (c UserTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.MapClaims.GetIssuedAt()
}
func (c UserTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.MapClaims.GetAudience()
}
func (c UserTokenClaims) GetIssuer() (string, error) {
	return c.MapClaims.GetIssuer()
}
func (c UserTokenClaims) GetSubject() (string, error) {
	return c.MapClaims.GetSubject()
}

func NewUserToken(userID uint64, role model.UserRole, secret string) (*userpb.UserToken, error) {
	expiresAt := time.Now().Add(24 * time.Hour)
	return NewUserTokenWithExpiration(userID, role, secret, expiresAt)
}

func NewUserTokenWithExpiration(userID uint64, role model.UserRole, secret string, expiresAt time.Time) (*userpb.UserToken, error) {
	claims := NewUserTokenClaimsWithExpiration(userID, role, expiresAt)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}

	return &userpb.UserToken{
		Token:     signedToken,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

func ValidateUserToken(tokenString, secret string) (*UserTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&UserTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
	)

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}
