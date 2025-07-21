package service

import (
	"context"
	"fmt"

	"github.com/oj-lab/user-service/internal/model"
	"github.com/oj-lab/user-service/internal/repository"
	"github.com/oj-lab/user-service/pkg/auth"
	"github.com/oj-lab/user-service/pkg/userpb"
)

type UserService interface {
	CreateUser(ctx context.Context, req *userpb.CreateUserRequest) error
	GetUser(ctx context.Context, id uint64) (*userpb.User, error)
	GetCurrentUser(ctx context.Context) (*userpb.User, error)
	GetUserByEmail(ctx context.Context, email string) (*userpb.User, error)
	GetUserByName(ctx context.Context, name string) (*userpb.GetUserByNameResponse, error)
	UpdateUser(ctx context.Context, req *userpb.UpdateUserRequest) error
	DeleteUser(ctx context.Context, id uint64) error
	ListUsers(ctx context.Context, req *userpb.ListUsersRequest) (*userpb.ListUsersResponse, error)
}

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) CreateUser(ctx context.Context, req *userpb.CreateUserRequest) error {
	user := &model.UserModel{
		Name:     req.Name,
		Email:    req.Email,
		GithubID: req.GithubId,
	}
	user.Role.FromPb(req.Role)

	return s.userRepo.Create(ctx, user)
}

func (s *userService) GetUser(ctx context.Context, id uint64) (*userpb.User, error) {
	user, err := s.userRepo.GetByID(ctx, uint(id))
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) GetCurrentUser(ctx context.Context) (*userpb.User, error) {
	// Get user info from context (set by auth interceptor)
	userInfo, ok := ctx.Value(auth.ContextKeyUserInfo).(*auth.UserInfo)
	if !ok {
		return nil, fmt.Errorf("user info not found in context")
	}

	return s.GetUser(ctx, userInfo.UserID)
}

func (s *userService) GetUserByEmail(ctx context.Context, email string) (*userpb.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) GetUserByName(ctx context.Context, name string) (*userpb.GetUserByNameResponse, error) {
	users, err := s.userRepo.GetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by name: %w", err)
	}

	response := &userpb.GetUserByNameResponse{
		Users: make([]*userpb.User, len(users)),
	}
	for i, user := range users {
		response.Users[i] = user.ToPb()
	}
	return response, nil
}

func (s *userService) UpdateUser(ctx context.Context, req *userpb.UpdateUserRequest) error {
	user, err := s.userRepo.GetByID(ctx, uint(req.Id))
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.UpdateFromPb(req)
	return s.userRepo.Update(ctx, user)
}

func (s *userService) DeleteUser(ctx context.Context, id uint64) error {
	return s.userRepo.Delete(ctx, uint(id))
}

func (s *userService) ListUsers(
	ctx context.Context,
	req *userpb.ListUsersRequest,
) (*userpb.ListUsersResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 10 // Default page size
	}
	offset := int((req.Page - 1) * req.PageSize)
	limit := int(req.PageSize)

	result := &userpb.ListUsersResponse{}
	count, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	if count > 0 {
		result.Total = uint64(count)
		users, err := s.userRepo.List(ctx, offset, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		result.Users = make([]*userpb.User, len(users))
		for i, user := range users {
			result.Users[i] = user.ToPb()
		}
	}
	return result, nil
}
