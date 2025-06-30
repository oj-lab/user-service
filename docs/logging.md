# Logging System Documentation

This document describes the improved logging system implemented for the user service.

## Overview

The logging system provides:
- **Structured logging** using Go's `slog` package
- **Request ID correlation** for tracing requests across the system
- **Configurable log levels** (debug, info, warn, error)
- **Multiple output formats** (text, json)
- **Context-aware logging** with automatic request metadata

## Configuration

### Environment Variables

Configure logging using these environment variables:

```bash
# Log level: debug, info, warn, error (default: info)
LOG_LEVEL=info

# Log format: text, json (default: text)
LOG_FORMAT=text
```

### Example Configurations

**Development (verbose text logging):**
```bash
export LOG_LEVEL=debug
export LOG_FORMAT=text
```

**Production (structured JSON logging):**
```bash
export LOG_LEVEL=info
export LOG_FORMAT=json
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
import "github.com/oj-lab/user-service/pkg/logger"

// Simple logging
logger.Info("operation completed", "user_id", 123, "action", "login")

// Context-aware logging (automatically includes request ID)
log := logger.WithContext(ctx)
log.Info("processing request", "operation", "user_creation")

// Error logging with structured data
logger.Error("database operation failed", 
    "error", err, 
    "table", "users", 
    "user_id", userID)
```

### Request ID Usage

Request IDs are automatically generated and propagated:

```go
// Generate and add to context
requestID := logger.GenerateRequestID()
ctx = logger.WithRequestID(ctx, requestID)

// All subsequent logging will include the request ID
log := logger.WithContext(ctx)
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

### Breaking Changes
- Replaced inconsistent `log.Fatalf` and `slog.Info` with centralized logger
- All fatal errors now use structured logging before exit

### Backward Compatibility
- Existing log statements continue to work during transition
- Gradual migration path allows incremental adoption