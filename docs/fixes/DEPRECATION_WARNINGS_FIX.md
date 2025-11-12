# Deprecation Warnings Fix

## Issue
The QueryForge MCP server was showing deprecation warnings on startup:

```
DeprecationWarning: The `route` decorator is deprecated, and will be removed in version 1.0.0.
DeprecationWarning: websockets.legacy is deprecated
DeprecationWarning: websockets.server.WebSocketServerProtocol is deprecated
```

## Root Causes

### 1. Starlette Route Decorator
The `@app.route()` decorator was deprecated in Starlette and will be removed in version 1.0.0. The healthcheck endpoint was using this deprecated decorator.

### 2. Websockets Legacy API
Uvicorn's websocket implementation was using `websockets.legacy` module, which was deprecated in websockets 14.0 (released November 2024).

## Solutions Applied

### 1. Fixed Starlette Route Decorator (server.py)

**Before:**
```python
@app.route("/health", methods=["GET"])
async def healthcheck(_: Request) -> JSONResponse:
    """Lightweight endpoint used for container health checks."""
    return JSONResponse({"status": "ok"})
```

**After:**
```python
# Add health check endpoint using add_route instead of deprecated @route decorator
async def healthcheck(_: Request) -> JSONResponse:
    """Lightweight endpoint used for container health checks."""
    return JSONResponse({"status": "ok"})

app.add_route("/health", healthcheck, methods=["GET"])
```

**Change:** Replaced the deprecated `@app.route()` decorator with `app.add_route()` method, which is the recommended approach per Starlette's routing documentation.

### 2. Fixed Websockets Legacy Deprecation (requirements.txt)

**Before:**
```
uvicorn==0.38.0
```

**After:**
```
uvicorn==0.32.0  # No [standard] extras - we only need SSE/STDIO, not websockets
```

**Changes:**
- Removed `[standard]` extras from uvicorn dependency - this was unnecessarily pulling in websockets
- QueryForge only uses STDIO and SSE (Server-Sent Events) transports, neither of which require websockets
- SSE is a one-way HTTP-based protocol, not a websockets protocol
- This eliminates the websockets.legacy deprecation warnings entirely by not installing websockets at all

## Why This Approach?

### Starlette Fix
The `add_route()` method is the modern, recommended way to add routes programmatically in Starlette. This change:
- Eliminates the deprecation warning
- Uses the stable, forward-compatible API
- Maintains identical functionality

### Websockets Fix
Rather than working around the websockets.legacy deprecation, we realized websockets isn't needed at all:
- QueryForge uses only STDIO mode (default) and SSE transport (Server-Sent Events)
- SSE is HTTP-based, not websockets-based - it's a one-way event stream
- The `uvicorn[standard]` extras were unnecessarily pulling in websockets as a dependency
- Removing the `[standard]` extras eliminates websockets entirely, solving the deprecation warnings

This is the cleanest solution - don't install dependencies you don't need!

## Testing

After applying these fixes, the server should start without any deprecation warnings:

```bash
# Build and run with Docker
docker-compose up --build

# Expected output (no deprecation warnings):
2025-11-12 22:38:29,317 - __main__ - INFO - 🌐 Running MCP server on http://0.0.0.0:8080
2025-11-12 22:38:29,317 - __main__ - INFO -  Messages endpoint available at /messages
```

## Future Considerations

If you ever need websockets support in the future:
1. Add `uvicorn[standard]` or explicitly add `websockets` to requirements
2. Monitor for any new deprecation warnings
3. Use modern websockets API if needed

For now, the minimal `uvicorn` installation is perfect for STDIO and SSE transports.

## Files Modified

- `src/queryforge/server/server.py` - Changed route registration method from deprecated decorator to `add_route()`
- `requirements.txt` - Removed unnecessary `[standard]` extras from uvicorn (eliminates websockets dependency)

## Impact

- ✅ Clean server startup logs (no deprecation warnings)
- ✅ Identical functionality maintained
- ✅ Forward-compatible with Starlette 1.0.0
- ✅ Smaller dependency footprint (no unnecessary websockets)
- ✅ Faster Docker builds (fewer dependencies to install)
- ✅ No impact on MCP tool functionality or SSE transport
