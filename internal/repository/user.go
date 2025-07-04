package repository

import (
	"context"

	"github.com/oj-lab/user-service/internal/model"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(ctx context.Context, user *model.UserModel) error
	GetByID(ctx context.Context, id uint) (*model.UserModel, error)
	GetByEmail(ctx context.Context, email string) (*model.UserModel, error)
	GetByGithubID(ctx context.Context, githubID string) (*model.UserModel, error)
	Update(ctx context.Context, user *model.UserModel) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, offset, limit int) ([]*model.UserModel, error)
	Count(ctx context.Context) (int64, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *model.UserModel) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) GetByID(ctx context.Context, id uint) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetByGithubID(
	ctx context.Context,
	githubID string,
) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).Where("github_id = ?", githubID).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *model.UserModel) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&model.UserModel{}, id).Error
}

func (r *userRepository) List(ctx context.Context, offset, limit int) ([]*model.UserModel, error) {
	var users []*model.UserModel
	err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&users).Error
	return users, err
}

func (r *userRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.UserModel{}).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
