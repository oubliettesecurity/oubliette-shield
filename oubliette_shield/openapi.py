"""
Oubliette Shield - OpenAPI/Swagger Documentation
Static OpenAPI 3.0 spec and Swagger UI endpoint.
"""

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Oubliette Shield API",
        "description": (
            "AI LLM Firewall - Protect LLM applications from prompt injection, "
            "jailbreak, and adversarial attacks.\n\n"
            "The Shield API provides endpoints for analyzing user messages, "
            "managing sessions, and monitoring system health."
        ),
        "version": "0.2.0",
        "contact": {
            "name": "Oubliette Security",
            "email": "info@oubliettesecurity.com",
        },
        "license": {
            "name": "Apache 2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0",
        },
    },
    "servers": [
        {
            "url": "/shield",
            "description": "Shield Blueprint (default prefix)",
        }
    ],
    "security": [{"ApiKeyAuth": []}],
    "paths": {
        "/analyze": {
            "post": {
                "summary": "Analyze a message for prompt injection",
                "description": (
                    "Run a user message through the full detection pipeline: "
                    "sanitization, pre-filter, ML scoring, and LLM judge."
                ),
                "operationId": "analyzeMessage",
                "tags": ["Detection"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/AnalyzeRequest"},
                            "example": {
                                "message": "What is the weather today?",
                                "session_id": "user-123",
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Analysis result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AnalyzeResponse"},
                                "example": {
                                    "verdict": "SAFE",
                                    "blocked": False,
                                    "detection_method": "ml_only",
                                    "ml_score": 0.05,
                                    "ml_threat_type": "none",
                                    "llm_verdict": None,
                                    "sanitizations": [],
                                    "session_escalated": False,
                                },
                            }
                        },
                    },
                    "400": {
                        "description": "Invalid request (empty or oversized message)",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"},
                            }
                        },
                    },
                    "401": {
                        "description": "Unauthorized - invalid API key",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"},
                            }
                        },
                    },
                    "429": {
                        "description": "Rate limit exceeded",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"},
                            }
                        },
                    },
                },
            }
        },
        "/health": {
            "get": {
                "summary": "Health check",
                "description": "Returns shield status, version, and active session count.",
                "operationId": "healthCheck",
                "tags": ["System"],
                "security": [],
                "responses": {
                    "200": {
                        "description": "Health status",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"},
                                "example": {
                                    "shield": "healthy",
                                    "version": "0.2.0",
                                    "active_sessions": 5,
                                },
                            }
                        },
                    }
                },
            }
        },
        "/sessions": {
            "get": {
                "summary": "List active sessions",
                "description": "Returns summary of all tracked sessions including threat counts and escalation status.",
                "operationId": "listSessions",
                "tags": ["Sessions"],
                "responses": {
                    "200": {
                        "description": "Session list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SessionsResponse"},
                            }
                        },
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"},
                            }
                        },
                    },
                },
            }
        },
        "/dashboard": {
            "get": {
                "summary": "Shield dashboard",
                "description": "HTML dashboard showing pipeline status, thresholds, and session statistics.",
                "operationId": "dashboard",
                "tags": ["System"],
                "responses": {
                    "200": {
                        "description": "HTML dashboard page",
                        "content": {"text/html": {"schema": {"type": "string"}}},
                    }
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key set via OUBLIETTE_API_KEY environment variable. Optional if not configured.",
            }
        },
        "schemas": {
            "AnalyzeRequest": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The user message to analyze",
                        "maxLength": 10000,
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session identifier for multi-turn tracking",
                        "default": "default",
                    },
                },
            },
            "AnalyzeResponse": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["SAFE", "MALICIOUS", "SAFE_REVIEW"],
                        "description": "Detection verdict",
                    },
                    "blocked": {
                        "type": "boolean",
                        "description": "Whether the message was blocked",
                    },
                    "detection_method": {
                        "type": "string",
                        "enum": ["pre_filter", "ml_only", "llm_only", "ensemble", "escalation", "sanitization_rejection"],
                        "description": "Which detection tier produced the verdict",
                    },
                    "ml_score": {
                        "type": "number",
                        "nullable": True,
                        "description": "ML anomaly score (0.0-1.0)",
                    },
                    "ml_threat_type": {
                        "type": "string",
                        "nullable": True,
                        "description": "ML-identified threat category",
                    },
                    "llm_verdict": {
                        "type": "string",
                        "nullable": True,
                        "description": "LLM judge verdict",
                    },
                    "sanitizations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sanitization types applied to input",
                    },
                    "session_escalated": {
                        "type": "boolean",
                        "description": "Whether the session has been escalated",
                    },
                },
            },
            "HealthResponse": {
                "type": "object",
                "properties": {
                    "shield": {"type": "string"},
                    "version": {"type": "string"},
                    "active_sessions": {"type": "integer"},
                },
            },
            "SessionsResponse": {
                "type": "object",
                "properties": {
                    "sessions": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/SessionSummary"},
                    },
                    "total": {"type": "integer"},
                },
            },
            "SessionSummary": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "interactions": {"type": "integer"},
                    "threat_count": {"type": "integer"},
                    "escalated": {"type": "boolean"},
                    "attack_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
            "Error": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                },
            },
        },
    },
    "tags": [
        {"name": "Detection", "description": "Message analysis and threat detection"},
        {"name": "Sessions", "description": "Session management and tracking"},
        {"name": "System", "description": "Health checks and system information"},
    ],
}


SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Oubliette Shield - API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; background: #1a1a2e; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui { max-width: 1200px; margin: 0 auto; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: './openapi.json',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis],
            layout: 'BaseLayout',
            deepLinking: true,
        });
    </script>
</body>
</html>"""
