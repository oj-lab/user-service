package handler

import (
	"context"

	"github.com/oj-lab/user-service/internal/service"
	"github.com/oj-lab/user-service/pkg/userpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UserHandler struct {
	userService service.UserService
	userpb.UnimplementedUserServiceServer
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

func (h *UserHandler) CreateUser(
	ctx context.Context,
	req *userpb.CreateUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) GetUser(
	ctx context.Context,
	req *userpb.GetUserRequest,
) (*userpb.User, error) {
	return h.userService.GetUser(ctx, req.Id)
}

func (h *UserHandler) GetUserByName(
	ctx context.Context,
	req *userpb.GetUserByNameRequest,
) (*userpb.GetUserByNameResponse, error) {
	return h.userService.GetUserByName(ctx, req.Name)
}

func (h *UserHandler) GetUserByEmail(
	ctx context.Context,
	req *userpb.GetUserByEmailRequest,
) (*userpb.User, error) {
	return h.userService.GetUserByEmail(ctx, req.Email)
}

func (h *UserHandler) UpdateUser(
	ctx context.Context,
	req *userpb.UpdateUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.UpdateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) DeleteUser(
	ctx context.Context,
	req *userpb.DeleteUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.DeleteUser(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) ListUsers(
	ctx context.Context,
	req *userpb.ListUsersRequest,
) (*userpb.ListUsersResponse, error) {
	resp, err := h.userService.ListUsers(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *UserHandler) GetCurrentUser(
	ctx context.Context,
	req *emptypb.Empty,
) (*userpb.User, error) {
	return h.userService.GetCurrentUser(ctx)
}
