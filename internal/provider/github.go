package provider

import (
	"context"
	"fmt"
	"net/url"

	"github.com/google/go-github/v73/github"
)

type GitHubProvider struct {
	apiBaseURL string
}

func NewGitHubProvider(apiBaseURL string) *GitHubProvider {
	return &GitHubProvider{
		apiBaseURL: apiBaseURL,
	}
}

func (g *GitHubProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	client := github.NewClient(nil).WithAuthToken(token)

	if g.apiBaseURL != "" {
		baseURL, err := url.Parse(g.apiBaseURL)
		if err != nil {
			return UserInfo{}, fmt.Errorf("invalid API base URL: %v", err)
		}
		client.BaseURL = baseURL
	}

	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return UserInfo{}, err
	}
	return UserInfo{
		ID:        fmt.Sprintf("%d", user.GetID()),
		Name:      user.GetName(),
		Email:     user.GetEmail(),
		AvatarURL: user.GetAvatarURL(),
	}, nil
}
