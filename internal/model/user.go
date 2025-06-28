package model

import (
	"time"

	"github.com/oj-lab/user-service/pkg/userpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type UserRole string

const (
	UserRoleUser  UserRole = "user"
	UserRoleAdmin UserRole = "admin"
)

func (role UserRole) ToPb() userpb.UserRole {
	switch role {
	case UserRoleUser:
		return userpb.UserRole_USER
	case UserRoleAdmin:
		return userpb.UserRole_ADMIN
	default:
		return userpb.UserRole_USER // Default to user if unknown
	}
}

func (role *UserRole) FromPb(pbRole userpb.UserRole) {
	switch pbRole {
	case userpb.UserRole_USER:
		*role = UserRoleUser
	case userpb.UserRole_ADMIN:
		*role = UserRoleAdmin
	default:
		*role = UserRoleUser // Default to user if unknown
	}
}

type UserModel struct {
	gorm.Model
	Name           string     `gorm:"type:varchar(100);not null"             json:"name"`
	Email          string     `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	HashedPassword *string    `gorm:"column:hashed_password"                 json:"-"`
	GithubID       *string    `gorm:"column:github_id;unique"                json:"github_id"`
	LastLoginAt    *time.Time `                                              json:"last_login_at"`
	Role           UserRole   `gorm:"type:varchar(20);default:'user'"        json:"role"`
}

func (UserModel) TableName() string {
	return "users"
}

func (u *UserModel) ToPb() *userpb.User {
	return &userpb.User{
		Id:        uint64(u.ID),
		Name:      u.Name,
		Email:     u.Email,
		GithubId:  u.GithubID,
		Role:      u.Role.ToPb(),
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
	}
}

func (u *UserModel) UpdateFromPb(req *userpb.UpdateUserRequest) {
	if req.Name != nil {
		u.Name = *req.Name
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.GithubId != nil {
		u.GithubID = req.GithubId
	}
	if req.Role != nil {
		u.Role.FromPb(*req.Role)
	}
}
