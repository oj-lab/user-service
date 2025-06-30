package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/oj-lab/user-service/configs"
)

func TestLogger_Init(t *testing.T) {
	// Test text format initialization
	cfg := configs.LogConfig{
		Level:  "info",
		Format: "text",
	}
	Init(cfg)

	// Test that logger is properly initialized by logging a message
	Info("test message", "key", "value")
}

func TestLogger_InitJSON(t *testing.T) {
	// Test JSON format initialization
	cfg := configs.LogConfig{
		Level:  "debug",
		Format: "json",
	}
	Init(cfg)

	// Test that logger is properly initialized by logging a message
	Debug("test debug message", "debug_key", "debug_value")
}

func TestLogger_LogLevels(t *testing.T) {
	cfg := configs.LogConfig{
		Level:  "debug",
		Format: "text",
	}
	Init(cfg)

	// Test all log levels
	Debug("debug message", "level", "debug")
	Info("info message", "level", "info")
	Warn("warn message", "level", "warn")
	Error("error message", "level", "error")
}

func TestLogger_WithContext(t *testing.T) {
	cfg := configs.LogConfig{
		Level:  "info",
		Format: "text",
	}
	Init(cfg)

	// Test context-aware logging
	ctx := context.Background()
	requestID := GenerateRequestID()
	ctx = WithRequestID(ctx, requestID)

	logger := WithContext(ctx)
	logger.Info("test context logging", "operation", "test")

	// Verify request ID is in context
	if GetRequestID(ctx) != requestID {
		t.Errorf("Expected request ID %s, got %s", requestID, GetRequestID(ctx))
	}
}

func TestLogger_RequestIDGeneration(t *testing.T) {
	// Test request ID generation
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	if id1 == id2 {
		t.Error("Request IDs should be unique")
	}

	if !strings.HasPrefix(id1, "req-") {
		t.Error("Request ID should have 'req-' prefix")
	}

	if len(id1) < 8 {
		t.Error("Request ID should be reasonably long")
	}
}

func TestLogger_ParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"invalid", slog.LevelInfo}, // default
		{"", slog.LevelInfo},        // default
	}

	for _, test := range tests {
		result := parseLevel(test.input)
		if result != test.expected {
			t.Errorf("parseLevel(%s) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestLogger_JSONOutput(t *testing.T) {
	// Capture output for testing
	var buf bytes.Buffer
	
	// Create a JSON handler writing to our buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	testLogger := slog.New(handler)
	
	// Set as default temporarily
	old := slog.Default()
	slog.SetDefault(testLogger)
	defer slog.SetDefault(old)

	// Log a message
	testLogger.Info("test json message", "key1", "value1", "key2", 42)

	// Verify JSON format
	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output, got empty string")
	}

	// Try to parse as JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("Failed to parse JSON output: %v", err)
	}

	// Verify required fields
	if logEntry["msg"] != "test json message" {
		t.Errorf("Expected msg='test json message', got %v", logEntry["msg"])
	}
	if logEntry["key1"] != "value1" {
		t.Errorf("Expected key1='value1', got %v", logEntry["key1"])
	}
	if logEntry["key2"] != float64(42) { // JSON numbers are float64
		t.Errorf("Expected key2=42, got %v", logEntry["key2"])
	}
}