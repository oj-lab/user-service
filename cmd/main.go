package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/oj-lab/go-webmods/app"
	"github.com/oj-lab/go-webmods/gorm_client"
	"github.com/oj-lab/go-webmods/grpc_utils/interceptor"
	"github.com/oj-lab/go-webmods/redis_client"
	"github.com/oj-lab/user-service/configs"
	"github.com/oj-lab/user-service/internal/handler"
	"github.com/oj-lab/user-service/internal/model"
	"github.com/oj-lab/user-service/internal/repository"
	"github.com/oj-lab/user-service/internal/service"
	"github.com/oj-lab/user-service/pkg/auth"
	"github.com/oj-lab/user-service/pkg/userpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func init() {
	cwd, _ := os.Getwd()
	app.SetCMDName("user_service")
	app.Init(cwd)
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func main() {
	cfg := configs.Load()

	// Initialize database
	db := gorm_client.NewDB(cfg.Database)
	db.AutoMigrate(&model.UserModel{})

	// Initialize Redis client
	rdb := redis_client.NewRDB(cfg.Redis)

	// Initialize repositories and services
	userRepo := repository.NewUserRepository(db)
	userService := service.NewUserService(userRepo)

	// Initialize handlers
	userHandler := handler.NewUserHandler(userService)
	authHandler := handler.NewAuthHandler(db, rdb)

	// Define public methods that don't require authentication
	publicMethods := map[string]bool{
		userpb.AuthService_GetOAuthCodeURL_FullMethodName: true,
		userpb.AuthService_LoginByOAuth_FullMethodName:    true,
		userpb.AuthService_LoginByPassword_FullMethodName: true,
		userpb.AuthService_GetUserToken_FullMethodName:    true,
	}

	// Setup gRPC server with auth interceptor
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.RequestIDInterceptor,
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
			auth.BuildAuthInterceptor(publicMethods, cfg.Auth.JWTSecret),
		),
	)
	userpb.RegisterUserServiceServer(grpcServer, userHandler)
	userpb.RegisterAuthServiceServer(grpcServer, authHandler)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	slog.Info("user service started", "port", cfg.Server.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func NewDB(cfg configs.Config) *gorm.DB {
	driver := cfg.Database.Driver
	switch driver {
	case "postgres":
		db, err := openPostgres(cfg)
		if err != nil {
			panic(err)
		}
		return db
	default:
		panic(fmt.Sprintf("unsupported database driver: %s", driver))
	}
}

func openPostgres(cfg configs.Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Username,
		cfg.Database.Name,
		cfg.Database.Password,
		cfg.Database.SSLMode,
	)
	db, err = gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, err
	}
	return db, nil
}
