package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/casbin/casbin/v2"
)

// NewEnforcer creates a new Casbin enforcer with the RBAC model and policy
func NewEnforcer() (*casbin.Enforcer, error) {
	// Get current working directory and find the configs
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	
	// Look for configs directory from current directory and parent directories
	var modelPath, policyPath string
	searchDir := cwd
	
	for i := 0; i < 5; i++ { // Search up to 5 levels up
		configsDir := filepath.Join(searchDir, "configs")
		modelCandidate := filepath.Join(configsDir, "rbac_model.conf")
		policyCandidate := filepath.Join(configsDir, "rbac_policy.csv")
		
		if _, err := os.Stat(modelCandidate); err == nil {
			if _, err := os.Stat(policyCandidate); err == nil {
				modelPath = modelCandidate
				policyPath = policyCandidate
				break
			}
		}
		
		// Move up one directory
		parentDir := filepath.Dir(searchDir)
		if parentDir == searchDir { // We've reached the root
			break
		}
		searchDir = parentDir
	}
	
	if modelPath == "" || policyPath == "" {
		return nil, fmt.Errorf("could not find rbac_model.conf or rbac_policy.csv in configs directory")
	}
	
	enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	
	return enforcer, nil
}

// CheckPermission checks if a user role has permission to access a method
func CheckPermission(enforcer *casbin.Enforcer, role, method string) (bool, error) {
	// For user service methods, we'll use "read" for Get operations and "write" for Create/Update/Delete
	action := getActionFromMethod(method)
	
	allowed, err := enforcer.Enforce(role, method, action)
	if err != nil {
		return false, fmt.Errorf("failed to enforce policy: %w", err)
	}
	
	return allowed, nil
}

// getActionFromMethod determines the action type based on the method name
func getActionFromMethod(method string) string {
	switch method {
	case "/UserService/GetUser", "/UserService/GetCurrentUser", "/UserService/ListUsers":
		return "read"
	case "/UserService/CreateUser", "/UserService/UpdateUser", "/UserService/DeleteUser":
		return "write"
	default:
		return "read" // Default to read for safety
	}
}