# Logging System Documentation

This document describes the logging system used in the user service.

## Overview

The logging system provides:
- **Structured logging** using Go's built-in `slog` package via go-webmods app initialization
- **Request ID correlation** for tracing requests across the system  
- **Configurable log levels and formats** through go-webmods configuration
- **Context-aware logging** with automatic request metadata

## Configuration

### Log Configuration

The logging system is automatically configured by `app.Init()` from the go-webmods package. Configuration is handled through the standard go-webmods config system.

Set log configuration in your config file or environment variables:

```bash
# Log level: debug, info, warn, error (default: info)
LOG_LEVEL=info

# Log format: json, plain-text, tint (default: tint for development)
LOG_FORMAT=json
```

### Example Configurations

**Development (colorized tint logging):**
```bash
export LOG_LEVEL=debug
export LOG_FORMAT=tint
```

**Production (structured JSON logging):**
```bash
export LOG_LEVEL=info
export LOG_FORMAT=json
```

## Usage

### Using slog Directly

Since `app.Init()` sets up the global slog logger, you can use `slog` directly throughout the application:

```go
import "log/slog"

func MyHandler(ctx context.Context) {
    slog.Info("processing request", "user_id", 123)
    slog.Error("operation failed", "error", err)
}
```

### Request ID Correlation

For request tracing, use the request context utilities:

```go
import (
    "log/slog"
    requestcontext "github.com/oj-lab/user-service/pkg/context"
)

func MyHandler(ctx context.Context, req *Request) {
    // Generate request ID for new requests
    requestID := requestcontext.GenerateRequestID()
    ctx = requestcontext.WithRequestID(ctx, requestID)
    
    // Create logger with request ID
    log := slog.With("request_id", requestID)
    
    log.Info("request started", "operation", "login")
    // ... handle request
    log.Info("request completed", "duration_ms", 42)
}
```

## Features

### 1. Request ID Correlation

Every request automatically gets a unique request ID that appears in all related log entries:

```
time=2025-06-30T10:48:42.263Z level=INFO msg="oauth login attempt started" request_id=req-15a6124488c8a2d9 ip_address=127.0.0.1
```

### 2. Structured Authentication Logging

The system logs all critical authentication events:

**OAuth Login Flow:**
- OAuth code URL generation
- State validation
- Token exchange
- User info retrieval
- User creation/login
- Session creation

**Password Login:**
- Login attempts (success/failure)
- Invalid credentials
- Account validation
- Session creation

**Token Generation:**
- JWT token requests
- Session validation
- Token generation success/failure

### 3. Session Management Logging

Session operations are fully logged:
- Session creation with expiration
- Session lookups and refreshes
- Invalid/expired session attempts

### 4. Security Event Logging

The system logs security-relevant events:
- Failed login attempts with IP addresses
- Invalid OAuth states
- Password verification failures
- Account access attempts

## Log Levels

### DEBUG
Detailed operational information, typically only enabled in development:
```
level=DEBUG msg="session refreshed successfully" user_id=123 session_id=req-15a6124488c8
```

### INFO
General information about successful operations:
```
level=INFO msg="oauth login completed successfully" user_id=123 provider=github is_new_user=false
```

### WARN
Warning conditions that don't prevent operation but may indicate issues:
```
level=WARN msg="password login failed" error="invalid password" user_id=123 ip_address=192.168.1.1
```

### ERROR
Error conditions that require attention:
```
level=ERROR msg="failed to create login session" error="redis connection failed" user_id=123
```

## Usage Examples

### In Code

```go
import (
    "log/slog"
    requestcontext "github.com/oj-lab/user-service/pkg/context"
)

// Simple logging
slog.Info("operation completed", "user_id", 123, "action", "login")

// Context-aware logging with request ID
requestID := requestcontext.GenerateRequestID()
ctx = requestcontext.WithRequestID(ctx, requestID)
log := slog.With("request_id", requestID)
log.Info("processing request", "operation", "user_creation")

// Error logging with structured data
slog.Error("database operation failed", 
    "error", err, 
    "table", "users", 
    "user_id", userID)
```

### Request ID Usage

Request IDs are generated and propagated through context:

```go
// Generate and add to context
requestID := requestcontext.GenerateRequestID()
ctx = requestcontext.WithRequestID(ctx, requestID)

// All subsequent logging will include the request ID
log := slog.With("request_id", requestID)
log.Info("processing authenticated request", "operation", "get_user")
```

## Output Examples

### Text Format (Development)
```
time=2025-06-30T10:48:42.263Z level=INFO msg="user created successfully" request_id=req-15a6124488c8a2d9 user_id=123 email=user@example.com role=user
time=2025-06-30T10:48:42.264Z level=INFO msg="session created successfully" request_id=req-15a6124488c8a2d9 user_id=123 session_id=req-a1b2c3d4e5f6 expires_in_hours=24
```

### JSON Format (Production)
```json
{"time":"2025-06-30T10:49:03.248Z","level":"INFO","msg":"oauth login attempt started","request_id":"req-15a6124488c8a2d9","provider":"github","ip_address":"192.168.1.1","user_agent":"Mozilla/5.0"}
{"time":"2025-06-30T10:49:03.249Z","level":"INFO","msg":"oauth login completed successfully","request_id":"req-15a6124488c8a2d9","user_id":123,"provider":"github","is_new_user":false,"ip_address":"192.168.1.1"}
```

## Monitoring and Alerting

### Key Log Patterns for Monitoring

**Failed Authentication Attempts:**
```
level=WARN msg="password login failed" error="invalid password"
level=WARN msg="oauth state validation failed"
```

**System Errors:**
```
level=ERROR msg="failed to create login session"
level=ERROR msg="failed to store session in redis"
```

**Security Events:**
```
level=WARN msg="password login attempt for oauth-only account"
level=WARN msg="session lookup failed" error="invalid or expired session"
```

### Recommended Alerts

1. **High Failed Login Rate**: Multiple failed login attempts from same IP
2. **Session Creation Failures**: Redis connectivity issues
3. **OAuth Flow Failures**: Provider integration issues
4. **Invalid Session Access**: Potential security issues

## Log Retention

- **Development**: Logs to stdout, no retention policy needed
- **Production**: Configure log aggregation system (ELK, Splunk, etc.) with appropriate retention
- **Recommended retention**: 90 days for audit logs, 30 days for operational logs

## Performance Impact

The structured logging system is designed for minimal performance impact:
- Lazy evaluation of log parameters
- Efficient JSON marshaling
- Context propagation without deep copying
- Request ID generation using crypto/rand for security

## Migration Notes

### Current Implementation
- Uses go-webmods `app.Init()` for logger setup instead of custom logger package
- Leverages standard `slog` package for all logging operations
- Request ID context utilities provided by `pkg/context` package

### Integration with go-webmods
- Log configuration automatically handled by go-webmods configuration system
- Global slog logger configured with hostname and command name metadata
- Supports multiple output formats: json, plain-text, and tint (colorized)