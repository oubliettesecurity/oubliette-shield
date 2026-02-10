"""
Oubliette Shield - FastAPI/ASGI Middleware
Provides ShieldMiddleware and shield_dependency for FastAPI applications.

Usage:
    from fastapi import FastAPI
    from oubliette_shield import Shield
    from oubliette_shield.fastapi_middleware import ShieldMiddleware, shield_dependency

    app = FastAPI()
    shield = Shield()

    # Option 1: Middleware (protects all configured paths)
    app.add_middleware(ShieldMiddleware, shield=shield, paths=["/chat", "/api/query"])

    # Option 2: Dependency injection (per-route)
    check = shield_dependency(shield)

    @app.post("/chat")
    async def chat(body: dict, analysis=Depends(check)):
        return {"response": "ok", "shield": analysis}
"""

import asyncio
import json


class ShieldMiddleware:
    """
    ASGI middleware that intercepts POST requests and runs Shield analysis.

    Args:
        app: ASGI application
        shield: Shield instance (creates default if None)
        paths: List of URL paths to protect (default: all POST paths)
        block_status: HTTP status code for blocked requests (default: 400)
        message_field: JSON field containing the user message (default: "message")
    """

    def __init__(self, app, shield=None, paths=None, block_status=400,
                 message_field="message"):
        self.app = app
        self.paths = paths
        self.block_status = block_status
        self.message_field = message_field

        if shield is None:
            from . import Shield
            self.shield = Shield()
        else:
            self.shield = shield

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")

        # Only intercept POST requests to configured paths
        if method != "POST" or (self.paths and path not in self.paths):
            await self.app(scope, receive, send)
            return

        # Read request body
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break

        # Parse JSON body
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON, pass through
            await self._replay_body(scope, body, send)
            return

        user_message = data.get(self.message_field, "")
        if not user_message:
            # No message field, pass through
            await self._replay_body(scope, body, send)
            return

        # Run Shield analysis
        session_id = data.get("session_id", "default")
        # Extract client IP from scope
        client = scope.get("client")
        source_ip = client[0] if client else "127.0.0.1"

        result = await asyncio.to_thread(
            self.shield.analyze, user_message,
            session_id=session_id, source_ip=source_ip,
        )

        if result.blocked:
            # Block the request
            response_body = json.dumps({
                "error": "Request blocked by Oubliette Shield",
                "verdict": result.verdict,
                "detection_method": result.detection_method,
            }).encode("utf-8")

            await send({
                "type": "http.response.start",
                "status": self.block_status,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(response_body)).encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": response_body,
            })
            return

        # Pass through to application with replayed body
        await self._replay_body(scope, body, send)

    async def _replay_body(self, scope, body, send):
        """Replay the buffered body to the downstream application."""
        body_sent = False

        async def receive_replay():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, receive_replay, send)


def shield_dependency(shield=None, message_field="message",
                      session_field="session_id", block=True):
    """
    Create a FastAPI dependency for Shield analysis.

    Args:
        shield: Shield instance (creates default if None)
        message_field: JSON field containing the user message
        session_field: JSON field containing session ID
        block: If True, raises HTTPException on malicious input

    Returns:
        Async dependency function for FastAPI's Depends()

    Usage:
        check = shield_dependency(shield)

        @app.post("/chat")
        async def chat(body: dict, analysis=Depends(check)):
            return {"response": "ok"}
    """
    if shield is None:
        from . import Shield
        _shield = Shield()
    else:
        _shield = shield

    async def _dependency(request):
        try:
            body = await request.json()
        except Exception:
            return None

        user_message = body.get(message_field, "")
        if not user_message:
            return None

        session_id = body.get(session_field, "default")
        source_ip = request.client.host if request.client else "127.0.0.1"

        result = await asyncio.to_thread(
            _shield.analyze, user_message,
            session_id=session_id, source_ip=source_ip,
        )

        if block and result.blocked:
            try:
                from fastapi import HTTPException
            except ImportError:
                raise RuntimeError("fastapi required for shield_dependency")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Request blocked by Oubliette Shield",
                    "verdict": result.verdict,
                    "detection_method": result.detection_method,
                },
            )

        return result.to_dict()

    return _dependency
