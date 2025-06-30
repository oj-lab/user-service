package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/oj-lab/user-service/configs"
)

var defaultLogger *slog.Logger

// Init initializes the global logger with the provided configuration
func Init(cfg configs.LogConfig) {
	var handler slog.Handler

	// Parse log level
	level := parseLevel(cfg.Level)

	// Create handler based on format
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// parseLevel converts string level to slog.Level
func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithContext returns a logger with context information
func WithContext(ctx context.Context) *slog.Logger {
	logger := defaultLogger
	if logger == nil {
		// Fallback to default slog if not initialized
		logger = slog.Default()
	}

	// Extract request ID from context if available
	if requestID := GetRequestID(ctx); requestID != "" {
		logger = logger.With("request_id", requestID)
	}

	return logger
}

// Info logs an info message with optional attributes
func Info(msg string, args ...any) {
	if defaultLogger != nil {
		defaultLogger.Info(msg, args...)
	} else {
		slog.Info(msg, args...)
	}
}

// Error logs an error message with optional attributes
func Error(msg string, args ...any) {
	if defaultLogger != nil {
		defaultLogger.Error(msg, args...)
	} else {
		slog.Error(msg, args...)
	}
}

// Warn logs a warning message with optional attributes
func Warn(msg string, args ...any) {
	if defaultLogger != nil {
		defaultLogger.Warn(msg, args...)
	} else {
		slog.Warn(msg, args...)
	}
}

// Debug logs a debug message with optional attributes
func Debug(msg string, args ...any) {
	if defaultLogger != nil {
		defaultLogger.Debug(msg, args...)
	} else {
		slog.Debug(msg, args...)
	}
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...any) {
	Error(msg, args...)
	os.Exit(1)
}